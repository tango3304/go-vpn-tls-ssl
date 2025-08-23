// TLSをベースに、「 多(クライアント) 対 一(サーバ) 」の簡易的なVPN通信。
// TUNインターフェースを作成し、クライアントからの接続を受け付ける。
// 接続を受け付けたクライアントに仮想IPアドレス(識別ID)を割り当て、パケットのルーティングを行う。
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/songgao/water"
)

// #############################
// 定数
// #############################
const (
	Protocol       = "tcp"        // VPN通信に利用するプロトコル
	CertFile       = "server.crt" // サーバ証明書ファイル
	KeyFile        = "server.key" // サーバ秘密鍵ファイル
	BuffSize       = 1500         // パケットの読み取り用バッファサイズ (MTUを参照)
	IPv4HeaderSize = 20           // IPv4ヘッダの最小値
)

// #############################
// フラグの定義
// # flag.String("オプション名", "デフォルト値", "フラグの説明"))
// #############################
var (
	tunName = flag.String("tun-name", "vpn0", "tun interface name")         //TUNインターフェースの名前
	tunIP   = flag.String("tun-ip", "10.0.0.46/24", "tun interface ipaddr") //TUNインターフェースのIPアドレス
	port    = flag.String("port", "4433", "vpn session port")               // VPN通信に利用するポート番号
)

// #############################
// 構造体
// #############################
// クライアントに割り当てる仮想IPアドレスの割り当て状況を管理する。
type IPManager struct {
	pool   map[string]bool // IPアドレスが使用中か確認（True=使用中）
	subnet *net.IPNet      // 割り当て可能なIPアドレスの範囲
	nextIP net.IP          // 次にクライアントに割り当てるIPアドレスの候補
	mutex  sync.Mutex      // poolとnextIPへの同時処理ができないように制御し、データの競合を防ぐ
}

// サーバーからクライアントへ通知する。
// クライアント側のネットワーク設定を定義する。
// JSON形式でやり取りを行う。
type VPNConfig struct {
	IP   string `json:"ip"`   // クライアントのTUNインターフェースに割り当てるIPアドレス
	CIDR int    `json:"cidr"` // サブネット範囲を示すCIDRプレフィックス長
}

// TLS接続に利用するLANインターフェースを定義する。
type NetworkInfo struct {
	ifaceName string   //インターフェースの名前
	ifaceIPs  []string //インターフェースのIPアドレス
}

// #############################
// メイン関数
// #############################
// VPNサーバーアプリケーションのエントリーポイント
func main() {
	// すべてのgoroutineの完了を待つためのWaitGroupを初期化。
	var wg sync.WaitGroup

	// コマンドラインから渡された引数を反映する。
	flag.Parse()

	// VPNサーバに割り当てるIPv4アドレスから、CIDR表記のIPアドレスを取得する。
	// 取得したIPアドレスは、クライアントに割り当てる仮想IPアドレスを生成する際に使用する。
	prefix, err := netip.ParsePrefix(*tunIP)
	if err != nil {
		log.Fatal(err)
	}
	cidr := prefix.Masked().String()

	// 致命的なエラーを受け取るためのチャネル
	errMsg := make(chan error, 10)

	// キャンセル通知を受け取って安全にゴルーチンを終了させる
	ctx, cancel := context.WithCancel(context.Background())

	// 「Ctrl+C (SIGINT)」などのOSシグナルを待機するためのチャネルを設定。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// CLI画面をクリアにする。
	fmt.Print("\033c")

	// 利用可能なインターフェースの中から、TLS接続で利用するインターフェースの選択する。
	ethName, err := getTLSConnectionInterface()
	if err != nil {
		log.Fatalf("LAN interface selection canceled: %v", err)
	}

	// クライアントに割り当てる仮想IPアドレスの管理表を作成
	ipManager, err := newIPmanager(cidr)
	if err != nil {
		log.Fatal(err)
	}

	// クライアントの割り当てた仮想IPアドレスとVPNサーバのTLSセッションの紐づけを行う自作のルーティングテーブルを作成する。
	routingTable := make(map[string]*tls.Conn)
	var routingTableMutex sync.Mutex

	// TUNインターフェースを作成および設定を行う。
	tunIface, err := setupTUN(*tunName, *tunIP, cidr, ethName)
	if err != nil {
		log.Fatal(err)
	}

	// プログラム処理時に、setupTUN関数で設定した「TUNデバイスとiptables」の設定が残らないように、全部の処理が終了後に設定を削除する。
	defer cleanupTUN(*tunName, cidr, ethName)

	// TLS接続の設定
	tlsListener, err := setupTLSserver(*port)
	if err != nil {
		log.Fatal(err)
	}

	// クライアントからの接続を待つ
	wg.Add(1)
	go acceptConnection(ctx, &wg, tunIface, tlsListener, errMsg, ipManager, routingTable, &routingTableMutex)

	// VPNサーバ -> クライアントへの下りの通信
	wg.Add(1)
	go readAndRoutingFromTUN(ctx, &wg, tunIface, routingTable, &routingTableMutex)

	// OSからのシグナルを受信するするまで待機
	select {
	case <-sig:
		log.Println("Close VPNserver connection")
	case err := <-errMsg:
		log.Println(err)
	}

	// 終了処理
	cancel()
	tlsListener.Close()
	tunIface.Close()
	wg.Wait()
}

// #############################
// 主要な機能
// #############################
// 新しいクライアントからの接続を断続的に待ち受ける。
func acceptConnection(ctx context.Context, wg *sync.WaitGroup, tunIface *water.Interface, tlsListener net.Listener, errMsg chan error, ipManager *IPManager, routingTable map[string]*tls.Conn, routingTableMutex *sync.Mutex) {
	defer wg.Done()

	// 複数のクライアントからの接続を順番に処理する。
	for {
		// 新しいクライアントからのTLS接続をブロックして待つ。
		// 新しいクライアントからの接続が来るか、リスナーが閉じるまで一時停止する。
		conn, err := tlsListener.Accept()
		if err != nil {
			select {
			// main関数からのシャットダウン通知( cancel() )が原因の場合、正常終了とみなしループを抜ける。
			// 「CTRL + c」で、プロセスを終了させたい場合に必要
			case <-ctx.Done():
				log.Println("Close accept connection")
				return
			// それ以外の予期せぬエラーの場合、mainに通知して次の接続待機に移る。
			default:
				errMsg <- fmt.Errorf("client TLSconnection accept failed: %w", err)
				continue
			}
		}

		// 接続の事前チェック
		// 受け入れた接続が、期待通りのTLS接続であるか型アサーションで確認する。
		// net.Conn型から*tls.Conn型にアサーションする
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			errMsg <- fmt.Errorf("accepted connection is not TLSconnection: %w", err)
			conn.Close()
			continue
		}

		// クライアントごとの設定
		// 接続してきたクライアントを一意に識別するためのID（仮想IPアドレス形式）を払い出す。
		connClientID, err := ipManager.Get()
		if err != nil {
			log.Printf("Failed to assign IPaddress: %v", err)
			conn.Close()
			continue
		}
		log.Printf("Client %s is connected and ID: %s is assigned to the Client", tlsConn.RemoteAddr(), connClientID)

		// クライアントにネットワーク設定情報を通知する。
		// ネットワーク設定情報を基に、クライアント側はTUNインターフェースを作成する。
		confToSend := VPNConfig{
			IP:   connClientID.String(),
			CIDR: 24,
		}

		// JSONをエンコードするためのエンコーダーを作成する。
		encoder := json.NewEncoder(tlsConn)

		// 作成した設定情報をJSON形式にエンコードし、TLS接続経由でクライアントに送信する。
		if err := encoder.Encode(confToSend); err != nil {
			log.Printf("failed to send config to client %s: %v", tlsConn.RemoteAddr(), err)
			conn.Close()

			// IPを割り当てたが通知に失敗したため、プールに返却する。
			ipManager.Release(connClientID)
			continue
		}

		// サーバ内部の自作のルーティングテーブルに、クライアント情報を登録する
		// クライアントに割り当てた仮想IPアドレスとTLS接続IDを紐づけ、下り通信( サーバ -> クライアント )のルーティングを可能にする。
		routingTableMutex.Lock()
		routingTable[connClientID.String()] = tlsConn
		routingTableMutex.Unlock()

		// クライアント専用のデータ転送をバックグラウンドで実行し、他の接続してきたクライアントからの受付をブロックさせない。
		wg.Add(1)
		go func(conn *tls.Conn, id net.IP) {
			defer wg.Done()

			// クライアントが切断されたら、割り当てられたIDを解放しルーティングテーブルから削除を行う。
			defer func() {
				log.Printf("Client %s has been disconnected and the ID: %s has been released", conn.RemoteAddr(), id)
				ipManager.Release(id)
				routingTableMutex.Lock()
				delete(routingTable, id.String())
				routingTableMutex.Unlock()
			}()

			// 「クライアント -> VPNサーバ」の上りのデータ転送を開始する。
			startForwardingFromClient(ctx, tunIface, conn)
		}(tlsConn, connClientID) // 引数として渡し、データ競合を防ぐ。
	}
}

// 特定のクライアントからの通信セッションの上り(クライアント -> VPNサーバ) のデータ転送を行う。
// クライアントごとに独立したゴルーチンを実行している。
func startForwardingFromClient(ctx context.Context, tunIface *water.Interface, tlsConn *tls.Conn) {
	// 処理終了時には、必ずクライアントとのTLS接続を閉じる。
	defer tlsConn.Close()

	// クライアントからTLS接続で送られてきたパケットを読み込み、読み込んだデータを受けるチャネルを作成する。
	dataChan := make(chan []byte, 10)
	// パケットの読み込みやTUNインターフェースへデータを書き込む際に、発生したエラーメッセージを受けるチャネルを作成する。
	errChan := make(chan error, 1)

	// クライアントからTLS接続で送られてきたパケットを読み込み、データを取得する。
	go func() {
		for {
			buf := make([]byte, BuffSize) // ループごとに新しいバッファを確保し、データ競合が発生しないようにする。
			readData, readErr := tlsConn.Read(buf)
			if readErr != nil {
				errChan <- readErr
				return
			}
			dataChan <- buf[:readData]
		}
	}()

	// 複数の非同期イベントを同時に待ち受ける。
	for {
		select {
		// main関数からのシャットダウン通知( cancel() )が原因の場合、正常終了とみなしループを抜ける。
		// 「CTRL + c」で、プロセスを終了させたい場合に必要
		case <-ctx.Done():
			return
		// ユーザ空間で受け取ったIPパケットを解析し、適切な宛先に転送する
		case data := <-dataChan:
			// Read()は、エラーなしで0バイトを返すことがあるため、不要な空のデータの書き込み処理を避けるために、データ長が0バイトより大きいかを確認する。
			if len(data) > 0 {
				// 読み取ったデータをカーネル空間のTUNインターフェースに書き込む。
				if _, writeErr := tunIface.Write(data); writeErr != nil {
					log.Printf("CRITICAL: failed write to TUNinterface: %v", writeErr)
					return
				}
			}
		// それ以外の予期せぬエラーの場合、ループを抜ける。
		case err := <-errChan:
			if fatalError(err) {
				log.Printf("failed reading from %s: %v", tlsConn.RemoteAddr(), err)
			}
			return
		}
	}
}

// VPNサーバからのTLSセッションの下り(VPNサーバ -> クライアント)のデータ転送を行う。(中央ルーター)
// VPNサーバ起動時に、単一のゴルーチンが実行され、カーネル空間のTUNインターフェースに届いたすべてのパケットを適切な宛先にルーティングを行う。
func readAndRoutingFromTUN(ctx context.Context, wg *sync.WaitGroup, tunIface *water.Interface, routingTable map[string]*tls.Conn, routingTableMutex *sync.Mutex) {
	defer wg.Done()

	// TUNインターフェースで受信したパケットを読み込み、読み込んだデータを受けるチャネルを作成する。
	dataChan := make(chan []byte, 10)
	// パケットの読み込みとTLSセッションへデータを書き込む際に、発生したエラーメッセージを受けるチャネルを作成する。
	errChan := make(chan error, 1)

	// TUNインターフェースで受信したパケットを読み込み、データを取得する。
	go func() {
		for {
			buf := make([]byte, BuffSize) // ループごとに新しいバッファを確保し、データ競合が発生しないようにする。
			readData, readErr := tunIface.Read(buf)
			if readErr != nil {
				errChan <- readErr
				return
			}
			dataChan <- buf[:readData]
		}
	}()

	// メインのイベントループ
	// 複数の非同期イベントを同時に待ち受ける。
	for {
		select {
		// main関数からのシャットダウン通知( cancel() )が原因の場合、正常終了とみなしループを抜ける。
		// 「CTRL + c」で、プロセスを終了させたい場合に必要
		case <-ctx.Done():
			return
		// ユーザ空間で受け取ったパケットを解析し、適切な宛先に転送する
		case data := <-dataChan:
			// IPヘッダのサイズは、IPv4では「20バイト - 60バイト」となる。
			// 読み込んだパケットのIPヘッダが20バイト未満の場合、破損している可能性がある。
			// その状態で後続の処理に渡すと致命的なエラーを引き起こす原因となるため、データが20バイト以上かを確認している。
			if len(data) < IPv4HeaderSize {
				continue
			}

			// IPヘッダの先頭から「16バイト - 20バイト」の宛先IPv4アドレスを取得する。
			destIP := net.IP(data[16:20])

			// 宛先IPアドレスをキーとし、自作のルーティングテーブルから紐づくクライアント接続を検索する。
			routingTableMutex.Lock()
			cliConn, found := routingTable[destIP.String()]
			routingTableMutex.Unlock()

			// 宛先が明確で転送が可能なパケットのみ、TLSセッションにデータを書き込み宛先に転送する。
			if found {
				// 読み取ったデータをカーネル空間のTLSセッションに書き込む。
				if _, writeErr := cliConn.Write(data); writeErr != nil {
					if !fatalError(writeErr) {
					} else {
						log.Printf("error writing to client %s: %v", cliConn.RemoteAddr(), writeErr)
					}
				}
			}
		// それ以外の予期せぬエラーの場合、ループを抜ける。
		case err := <-errChan:
			if fatalError(err) {
				log.Printf("fatal error in reading TUNinterface: %v", err)
			}
			return
		}
	}
}

// #############################
// ヘルパー関数
// #############################
// VPN通信の出入り口として仮想インターフェース(TUNデバイス)を作成する。
// OSレベル(カーネル空間)での設定を行う。
func setupTUN(tunName string, tunIP string, cidr string, ethName string) (*water.Interface, error) {
	// TUNインターフェースの作成に必要なパラメータを定義する。
	// 定義した「conf」を基に、カーネル空間に新しいTUNデバイスを作成する。
	// 作成したTUNデバイスは、カーネル空間とユーザ空間で連携するための窓口となる。
	conf := water.Config{DeviceType: water.TUN}
	conf.Name = tunName
	iface, err := water.New(conf)
	if err != nil {
		return nil, fmt.Errorf("creation for TUNinterface failed: %w", err)
	}

	// OSの基本的な機能のipコマンドを呼び出し、カーネル空間に作成したTUNデバイスに、IPアドレスとサブネット(CIDR表記)を割り当てる。
	if err := exec.Command("ip", "addr", "add", tunIP, "dev", iface.Name()).Run(); err != nil {
		iface.Close()
		return nil, fmt.Errorf("create TUNinterface failed: %w", err)
	}

	// 割り当てたTUNデバイスを有効化し、パケットの送受信を可能にする。
	if err := exec.Command("ip", "link", "set", iface.Name(), "up").Run(); err != nil {
		iface.Close()
		return nil, fmt.Errorf("TUN interface configuration failed: %w", err)
	}

	// IPフォエワーディングを有効にし、受診したパケットを別のインターフェースに転送する。
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		iface.Close()
		return nil, fmt.Errorf("ip fowarding setup failed: %w", err)
	}

	// cidr(例: 10.0.0.0/24) のプライベートネットワークから来た通信をethName(例: eth0) インターフェースのIPアドレスに変換し、パケットを送信する。
	if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", cidr, "-o", ethName, "-j", "MASQUERADE").Run(); err != nil {
		iface.Close()
		return nil, fmt.Errorf(": %w", err)
	}

	// TUNインターフェース(tunName) とLAN側インターフェース(ethName) 間で、パケットの転送を許可し、
	// ユーザー空間で暗号化したデータをカーネル空間のネットワークスタックを通して、LAN側インターフェースに転送する。
	if err := exec.Command("iptables", "-A", "FORWARD", "-i", tunName, "-o", ethName, "-j", "ACCEPT").Run(); err != nil {
		iface.Close()
		return nil, fmt.Errorf(": %w", err)
	}

	// TUNインターフェースからLANインターフェース経由で開始した通信の戻りのパケットを許可しつつ、LANインターフェースからTUNインターフェースへ意図しない新規の通信が開始されないようにブロックする。
	if err := exec.Command("iptables", "-A", "FORWARD", "-i", ethName, "-o", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run(); err != nil {
		iface.Close()
		return nil, fmt.Errorf(": %w", err)
	}

	return iface, nil
}

// プログラムが終了する度に、setupTUN関数で設定した「TUNデバイスとiptables」の設定を削除する。
func cleanupTUN(tunName string, cidr string, ethName string) {
	// カーネル空間に作成したTUNデバイスを削除する。
	if err := exec.Command("ip", "link", "delete", tunName).Run(); err != nil {
		log.Printf("failed delete tun interface %s: %v", tunName, err)
	}

	// cidr(例: 10.0.0.0/24) のプライベートネットワークから来た通信をethName(例: eth0) インターフェースのIPアドレスに変換の設定を削除する。
	if err := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-o", ethName, "-j", "MASQUERADE").Run(); err != nil {
		log.Printf("failed delete nat rule: %v", err)
	}

	// TUNインターフェース(tunName) とLAN側インターフェース(ethName) 間のパケット転送の許可を削除する。、
	if err := exec.Command("iptables", "-D", "FORWARD", "-i", tunName, "-o", ethName, "-j", "ACCEPT").Run(); err != nil {
		log.Printf("failed delete FORWARD rule (tun > eth): %v", err)
	}

	// TUNインターフェースからLANインターフェース経由で開始した通信の戻りのパケットの許可を削除する。
	if err := exec.Command("iptables", "-D", "FORWARD", "-i", ethName, "-o", tunName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run(); err != nil {
		log.Printf("failed delete FORWARD rule (eth > tun): %v", err)
	}
}

// サーバー証明書を読み込み、指定されたポートにて、クライアントからのTLS接続を待ち受けるためのリスナーソケットを作成する。
func setupTLSserver(port string) (net.Listener, error) {
	// サーバ証明書(公開鍵)と秘密鍵のペアをファイルから読み込み、TLS接続で利用可能な形式に解析する。
	certificate, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		return nil, fmt.Errorf("public and Private key analysis failed: %w", err)
	}

	// LS接続の設定情報(証明書など)を指定する。
	tlsConf := &tls.Config{Certificates: []tls.Certificate{certificate}}

	// ラップ：付け加える
	// listenerオブジェクト：内部的データ + ソケット操作の機能( Accept()やClose() など
	//
	// 指定したプロトコルとポートで、カーネル空間にTCPソケットを作成し、それをTLS機能でラップする。
	// TLS機能をラップすることで、リスナーソケット(待ち受け専用ソケット)が受け付ける全ての接続は、自動でTLSの暗号化と復号化がされる。
	// listenerオブジェクトは、ユーザー空間に作成されているが、それが指し示している本物のリスニングソケットはカーネル空間にある。
	// ユーザー空間で作成したlistenerオブジェクトは、ユーザ空間からカーネル空間のTCPソケットを遠隔操作を行う。
	listener, err := tls.Listen(Protocol, ":"+port, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("listening on TCP 4433 failed: %w", err)
	}
	fmt.Println()
	log.Printf("Listening port TCP 4433 ......")

	return listener, nil
}

// エラーが発生するたびに処理が停止しないように、予め想定しているエラーは正常と判断する。
// これにより、クライアントの切断がサーバー全体の停止を防いでいる。
func fatalError(err error) bool {
	if err == nil {
		return false
	}

	// EOFは、Read()がそれ以上入力データがないときに返すエラーで、入力データの正常な終了を通知するためにのみEOFを返します。
	// ErrClosedは、既に閉じたネットワーク接続、I/Oの完了前に閉じたネットワーク接続に対し、I/O呼び出しによりエラーが返され、Close()で閉じられた際に発生を想定いている。
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return false
	}

	// OSやライブラリが返す、接続終了時の一般的なエラーメッセージを想定している。
	errMsg := err.Error()
	if strings.Contains(errMsg, "broken pipe") ||
		strings.Contains(errMsg, "connection reset by peer") ||
		strings.Contains(errMsg, "use of closed network connection") ||
		strings.Contains(errMsg, "write tun: invalid argument") {
		return false
	}

	return true
}

// 実体：メモリ上に確保された構造体専用の領域に、具体的なデータが格納されているもの
// コンストラクタ関数：インスタンス/オブジェクトを、安全かつ確実に生成するための専用の関数
//
// IPManager構造体から新しいインスタンス(実体)を生成する
// 接続してきたクライアントに一意の識別ID（仮想IPアドレス形式）を払い出すために、有効なCIDRかを確認している。
func newIPmanager(cidr string) (*IPManager, error) {
	// CIDR表記のIPアドレス(例：192.0.2.1/24)を解析し、IPアドレス(例：192.0.2.1)とネットワーク(192.0.2.0/24)を返す。
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	// クライアントに割り当てる仮想IPアドレスの割り当て状況の管理表に、取得したIPアドレスとネットワークを設定する。
	return &IPManager{
		pool:   make(map[string]bool),
		subnet: subnet,
		nextIP: ip,
	}, nil

}

// クライアントに払い出す一意の識別ID（仮想IPアドレス形式）の利用状況を確認する。
// 払い出してない識別IDの場合、一意の識別IDと同等の仮想IPアドレスをクライアントに払い出す。
func (ipMgr *IPManager) Get() (net.IP, error) {
	// 同時接続してきたクライアント同士でのデータ競合を防ぐために、更新処理中はpoolとnextIPへの排他ロックを取得する。
	// この関数が終了する際に、ロックを自動的に解除する。
	ipMgr.mutex.Lock()
	defer ipMgr.mutex.Unlock()

	// nextIPを基点に、最大254回まで第四オクテットから順番にIPアドレスを1つずつ繰り上げ、利用可能なIPアドレスを探索する。
	currentIP := make(net.IP, len(ipMgr.nextIP))
	copy(currentIP, ipMgr.nextIP)
	for num := 0; num < 254; num++ {
		for octet := len(currentIP) - 1; octet >= 0; octet-- {
			currentIP[octet]++
			if currentIP[octet] > 0 {
				break
			}
		}

		// 指定したサブネット内のIPアドレスであること And 払い出ししていないID（仮想IPアドレス形式）であるかこと を確認する。
		if ipMgr.subnet.Contains(currentIP) && !ipMgr.pool[currentIP.String()] {
			// 利用宣言を行う。
			ipMgr.pool[currentIP.String()] = true
			// 次回探索時の出発点を今回払い出すIPアドレスに更新する。
			ipMgr.nextIP = currentIP
			return currentIP, nil
		}
	}
	// 利用可能なIPアドレスがない場合
	return nil, errors.New("no available IP addresses in the pool")
}

// 利用しなくなったIPアドレスを別のクライアントに払い出すために、解放する。
func (ipMgr *IPManager) Release(ip net.IP) {
	ipMgr.mutex.Lock()
	defer ipMgr.mutex.Unlock()
	delete(ipMgr.pool, ip.String())
}

// TLS接続にて利用するLANインターフェースを選択する。
func getTLSConnectionInterface() (string, error) {
	var choiceInterface NetworkInfo

	// 利用可能なインターフェースの一覧を取得する。
	availableIntfs, err := getAvailableIPv4Interfaces()
	if err != nil {
		return "", err
	}

	fmt.Print("\033c") // CLI画面をクリアにする。
	fmt.Println()
	fmt.Println(" リスト番号を入力してください")

	// TLS接続で暗号化パケットを宛先に送る際に、利用するインターフェースを選択する。
	for {
		fmt.Println("--------------------------------")
		fmt.Println(" # TLS接続で利用するLANインターフェースを選択してください")
		// 取得してきた利用可能なインターフェースをリスト番号で選択させる。
		for index, iface := range availableIntfs {
			joinIP := strings.Join(iface.ifaceIPs, ", ")
			fmt.Printf(" [%d] %s: %s\n", index+1, iface.ifaceName, joinIP)
		}
		fmt.Println("--------------------------------")
		fmt.Print(" リスト番号: ")

		userInputValue, err := askForUserInput()
		if err != nil {
			return "", err
		}

		// 入力値(リスト番号) の先頭と末尾の空白があれば取り除き、文字列から数値に型変換する。
		// 入力値がインターフェース一覧の件数より多いか少ないかを検証する。
		// 問題がなければ、後続処理に進み、入力値が無効な場合は、再度入力を実施する。
		listValue, err := strconv.Atoi(strings.TrimSpace(userInputValue))
		if err != nil || listValue < 1 || listValue > len(availableIntfs) {
			fmt.Print("\033c") // CLI画面をクリアにする。
			fmt.Println()
			fmt.Println(" 入力した値は無効な値です")
			fmt.Println(" リスト番号にある番号を入力してください")
			continue
		}
		// 有効なリスト番号が選択された場合、インターフェース名とIPv4アドレスの情報を保持する。
		choiceInterface = availableIntfs[listValue-1]
		return choiceInterface.ifaceName, nil
	}
}

// 利用可能なインターフェース名とそれに紐づいているIPアドレスを取得する。
func getAvailableIPv4Interfaces() ([]NetworkInfo, error) {
	var availableInterfaces []NetworkInfo // 利用可能なインターフェース

	// 全インターフェースの情報を取得する。
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain interface infomation: %w", err)
	}

	// IPv4アドレスが設定されているインターフェースのみ抽出する。
	for _, iface := range ifaces {
		// ループ事に新しいバッファを確保し、データ競合が発生しないようにする。
		var ips []string // 利用可能なインターフェースに設定されているIPv4アドレスを格納する。

		// 無効なインターフェースとループバックを除外
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// インターフェースに設定されているアドレス(IPv4/IPv6)を取得する。
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		// インターフェースに設定されているIPv4アドレスのみ取得する。
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())

			// IPv4アドレスのみを取得する。
			if err == nil && prefix.Addr().Is4() {
				ips = append(ips, prefix.Addr().String())
			}
		}
		// 利用可能なIPv4アドレスが1つでもあれば、インターフェース名とIPv4アドレスを取得する
		if len(ips) > 0 {
			availableInterfaces = append(availableInterfaces, NetworkInfo{
				ifaceName: iface.Name,
				ifaceIPs:  ips,
			})
		}
	}
	// 利用できるインターフェースがない場合のエラー処理
	if len(availableInterfaces) == 0 {
		return nil, fmt.Errorf("no available interface found: %w", err)
	}
	return availableInterfaces, nil
}

// ユーザの入力を待つ
func askForUserInput() (string, error) {
	inputChan := make(chan string)    // ユーザ入力を受け取る
	errMsgChan := make(chan error, 1) // 致命的なエラーを受け取るためのチャネル

	// 「Ctrl+C (SIGINT)」などのOSシグナルを待機するためのチャネルを設定。
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// main関数のシグナルに戻す
	defer func() {
		signal.Stop(sigChan)
		close(sigChan)
	}()

	// ユーザからの入力を判別し、標準入力以外は処理を終了する。
	go func() {
		// 標準入力の値を受け付ける。
		scanner := bufio.NewScanner(os.Stdin)

		// 「scanner.Scan()」で、入力待ちで処理をブロックしている。
		// EOF と I/Oエラーのどちらかを判別する。
		if !scanner.Scan() {
			err := scanner.Err()
			// nilの場合、「EOF」
			if err == nil {
				err = fmt.Errorf("input interrupted")
			}
			errMsgChan <- err
			return
		}
		// 標準入力した値(リスト番号) を取得する。
		inputChan <- scanner.Text()
	}()

	select {
	//　ユーザの標準入力
	case input := <-inputChan:
		return input, nil
	// 入力処理でエラー発生
	case err := <-errMsgChan:
		return "", err
	// 「Ctrl+C」などのOSシグナルを受信
	case <-sigChan:
		return "", errors.New("os signal receive")
	}
}

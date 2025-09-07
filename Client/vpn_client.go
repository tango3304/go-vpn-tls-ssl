package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// #############################
// 定数
// #############################
const (
	Protocol               = "tcp"              // VPN通信に利用するプロトコル
	BuffSize               = 1500               //パケットの読み取り用バッファサイズ (MTUを参照)
	MetricValue            = "50"               // メトリック値
	ResolvConfPath         = "/etc/resolv.conf" // NameServerの設定ファイルのパス
	DevNullPath            = "/dev/null"        // 標準出力と標準エラー出力の両方共を破棄する
	DNSResolver            = "resolvectl"       // 名前解決サービス
	DefaultRouteFirstHalf  = "0.0.0.0/1"        // 全IPアドレス空間の前半半分 (0.0.0.0 - 127.255.255.255)
	DefaultRouteSecondHalf = "128.0.0.0/1"      // 全IPアドレス空間の後半半分 (128.0.0.0 - 255.255.255.255)
)

// #############################
// フラグの定義
// # flag.String("オプション名", "デフォルト値", "フラグの説明"))
// #############################
var (
	svrIP   = flag.String("server-ip", "", "vpn server ip address")     // VPNサーバのIPアドレス
	tunName = flag.String("tun-name", "vpn0", "tun interface name")     //TUNインターフェースの名前
	port    = flag.String("port", "4433", "vpn session port")           // VPN通信に利用するポート番号
	dnsIP   = flag.String("dns-ip", "1.1.1.1", "dns server ip address") // 名前解決先のDNSサーバのIPアドレス
)

// #############################
// 構造体
// #############################
// サーバーからクライアントへ通知される
// クライアント側のネットワーク設定を定義
// JSON形式で受け取る
type VPNConfig struct {
	IP   string `json:"ip"`   // クライアントのTUNインターフェースに割り当てるIPアドレス
	CIDR int    `json:"cidr"` // サブネット範囲を示すCIDRプレフィックス長
}

// #############################
// メイン関数
// #############################
// VPNクライアントアプリケーションのエントリーポイント
func main() {
	// すべてのgoroutineの完了を待つためのWaitGroupを初期化する。
	var wg sync.WaitGroup

	// キャンセル通知を受け取って安全にゴルーチンを終了させる
	ctx, cancel := context.WithCancel(context.Background())

	// 「Ctrl+C (SIGINT)」などのOSシグナルを待機するためのチャネルを設定する。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// コマンドラインから渡された引数を反映する。
	flag.Parse()

	// 引数にVPNサーバのIPアドレスが指定されているかの確認をする。
	if *svrIP == "" {
		log.Println("ip address of the vpn server not been specified")
		flag.Usage()
		os.Exit(1)
	}

	// CLI画面をクリアにする。
	fmt.Print("\033c")

	// VPN通信で使うインターフェースを選択する。
	ifaceName, err := selectionLANInterfaceForVPNConnection()
	if err != nil {
		log.Fatal("failed to get for selected interface: ", err)
	}

	// TLS接続を確立する。
	dest := fmt.Sprintf("%s:%s", *svrIP, *port)
	tlsConn, err := setupTLSconnection(dest)
	if err != nil {
		log.Fatal(err)
	}

	// JSONをデコードするためのデコーダーを作成を作成する。
	decoder := json.NewDecoder(tlsConn)

	// 実体：メモリ上に確保された構造体専用の領域に、具体的なデータが格納されているもの
	//
	// サーバから受信したJSON形式でエンコードされた設定情報をデコーダーでデコードし、VPNConfig構造体から新しいインスタンス(実体)を作成する。
	var recvConf VPNConfig
	if err := decoder.Decode(&recvConf); err != nil {
		log.Fatalf("failed to unmarshal conf JSON: %v", err)
	}

	// JSON形式で受信した設定情報を基に、TUNインターフェースを作成および設定を行う。
	tunIface, defaultGateway, vpnIPMask, originalPath, backupPath, err := setupTUN(recvConf.IP, recvConf.CIDR, ifaceName)
	if err != nil {
		log.Fatal(err)
	}

	// プログラム処理後に、setupTUNdevice関数で設定した「TUNインターフェース」の設定が残らないように、全部の処理が終了後に設定を削除する。
	defer cleanupTUN(tunIface, originalPath, backupPath)

	// 下り(VPNサーバ -> クライアント) のデータ転送を行う。
	wg.Add(1)
	go startForwardingFromVPN(ctx, &wg, tunIface, tlsConn)

	// 上り(クライアント -> VPNサーバ) のデータ転送を行う。
	wg.Add(1)
	go readAndSentFromVPN(ctx, &wg, tunIface, tlsConn)

	// OSからのシグナルを受信するするまで待機
	<-sig
	log.Println("Close VPNserver connection")

	// 終了処理
	cancel()
	cleanupDefaultRoute(tunIface, defaultGateway, vpnIPMask)
	tlsConn.Close()
	tunIface.Close()
	wg.Wait()
}

// #############################
// 主要な機能
// #############################
// VPNサーバからの通信セッションの下り(VPNサーバ > クライアント) のデータ転送を行う。
func startForwardingFromVPN(ctx context.Context, wg *sync.WaitGroup, tunIface *water.Interface, tlsConn *tls.Conn) {
	defer wg.Done()

	// VPNサーバからTLS接続で送られてきたパケットを読み込み、読み込んだデータを受けるチャネルを作成する。
	dataChan := make(chan []byte, 10)

	// パケットの読み込みやTUNインターフェースへデータを書き込む際に、発生したエラーメッセージを受けるチャネルを作成する。
	errChan := make(chan error, 1)

	// VPNサーバからTLS接続で送られてきたパケットを読み込み、データを取得する。
	go func(tlsConn *tls.Conn, dataChan chan []byte) {
		for {
			buf := make([]byte, BuffSize) // ループごとに新しいバッファを確保し、データ競合が発生しないようにする。
			readData, readErr := tlsConn.Read(buf)
			if readErr != nil {
				errChan <- readErr
				return
			}
			dataChan <- buf[:readData]
		}
	}(tlsConn, dataChan)

	// 複数の非同期イベントを同時に待ち受ける。
	for {
		select {
		// main関数からのシャットダウン通知( cancel() )が原因の場合、正常終了とみなしループを抜ける。
		// 「CTRL + c」で、プロセスを終了させたい場合に必要
		case <-ctx.Done():
			return
		case data := <-dataChan:
			// 読み取ったデータをカーネル空間のTUNインターフェースに書き込む。
			if _, writeErr := tunIface.Write(data); writeErr != nil {
				log.Printf("CRITICAL: failed write to TUNinterface: %v", writeErr)
				return
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

// TUNインターフェースからデータを読み取り、クライアント(TLS)へ書き込む
// クライアント -> VPNサーバへの上りの通信転送
func readAndSentFromVPN(ctx context.Context, wg *sync.WaitGroup, tunIface *water.Interface, tlsConn *tls.Conn) {
	defer wg.Done()

	// // 読み込んだデータを受けるチャネルとエラーを受けるチャネルを作成
	dataChan := make(chan []byte, 10)
	errChan := make(chan error, 1)

	// TUNインターフェースで受信したパケットを読み込み、データを取得する。
	go func(tunIface *water.Interface, dataChan chan []byte) {
		for {
			buf := make([]byte, BuffSize) // ループごとに新しいバッファを確保し、データ競合が発生しないようにする。
			readData, readErr := tunIface.Read(buf)
			if readErr != nil {
				errChan <- readErr
				return
			}
			dataChan <- buf[:readData]
		}
	}(tunIface, dataChan)

	// メインのイベントループ。select文を使い、複数の非同期イベントを同時に待ち受ける。
	// 1段目：中断通知の処理、2段目：データの書き込み、3段目：エラー時の処理
	for {
		select {
		// main関数からのシャットダウン通知( cancel() )が原因の場合、正常終了とみなしループを抜ける。
		// 「CTRL + c」で、プロセスを終了させたい場合に必要
		case <-ctx.Done():
			return
		case data := <-dataChan:
			// TLS接続に書き込む
			if _, writeErr := tlsConn.Write(data); writeErr != nil {
				if fatalError(writeErr) {
					log.Printf("error writing to TLS: %v", writeErr)
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
// 指定されたVPNサーバのIPv4アドレスに対して、TLS接続を確立する。
func setupTLSconnection(dest string) (*tls.Conn, error) {
	// TLS接続の設定
	// InsecureSkipVerify が「True」の場合は、証明書の検証をスキップする。
	// 証明書の検証スキップは、セキュリティインシデントになる可能性がある。
	// そのため、検証環境では「True」にしてはいけない。
	conf := &tls.Config{InsecureSkipVerify: true}

	// 指定したプロトコルと宛先に、TLSハンドシェイクを開始する。
	// 内部では、3WayHandshakeでTCP接続を確立し、TLS Handshake でTLS接続をネゴシエーションしている。
	conn, err := tls.Dial(Protocol, dest, conf)
	if err != nil {
		return nil, fmt.Errorf("VPNserver connection failed: %w", err)
	}
	fmt.Println()
	log.Println(": VPNserver connection success")

	return conn, nil
}

// VPN通信の出入り口として仮想インターフェース(TUNデバイス)を作成する。
// OSレベル(カーネル空間)での設定を行う。
func setupTUN(ipAddr string, cidr int, ifaceName string) (*water.Interface, string, string, string, string, error) {
	// 動的IPアドレスを設定する。
	dynamicIP := fmt.Sprintf("%s/%d", ipAddr, cidr)
	log.Printf("Set TUNinterface IPAddr: %s", dynamicIP)

	// TUNインターフェースの作成と作成したTUNインターフェースのデフォルトルートの設定を行う。
	tunIface, defaultGateway, vpnIPMask, err := setupIface(dynamicIP, ifaceName)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("failed to create tun interface: %w", err)
	}

	// デフォルトゲートルートを設定したTUNデバイスに、DNSサーバを割り当てる。
	// DNSサーバを割り当てることにより、FQDNのアクセス時でも名前解決を行うことができる。
	originalPath, backupPath, err := setupDNS(tunIface)
	if err != nil {
		tunIface.Close()
		return nil, "", "", "", "", fmt.Errorf("failed to processing the setup dns: %w", err)
	}

	return tunIface, defaultGateway, vpnIPMask, originalPath, backupPath, nil
}

// 新規のTUNインターフェースを作成する
func setupIface(dynamicIP string, ifaceName string) (*water.Interface, string, string, error) {
	// TUNデバイスの作成に必要なパラメータを定義する。
	// 定義した「conf」を基に、カーネル空間に新しいTUNデバイスを作成する。
	// 作成したTUNデバイスは、カーネル空間とユーザ空間で連携するための窓口となる。
	conf := water.Config{DeviceType: water.TUN}
	conf.Name = *tunName
	tunIface, err := water.New(conf)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to create new tun/tap interface: %w", err)
	}

	// OSの基本的な機能のipコマンドを呼び出し、カーネル空間に作成したTUNデバイスに、IPアドレスとサブネット(CIDR表記)を割り当てる。
	if err := exec.Command("ip", "addr", "add", dynamicIP, "dev", tunIface.Name()).Run(); err != nil {
		tunIface.Close()
		return nil, "", "", fmt.Errorf("failed to create new tun interfacae: %w", err)
	}

	// 割り当てたTUNデバイスを有効化し、パケットの送受信を可能にする。
	if err := exec.Command("ip", "link", "set", tunIface.Name(), "up").Run(); err != nil {
		tunIface.Close()
		return nil, "", "", fmt.Errorf("failed to configuration to tun interface: %w", err)
	}

	// 既存のデフォルトルートより優先度の高いメトリックで、新しくTUNインターフェースのデフォルトルートを追加する。
	if err := exec.Command("ip", "route", "add", "default", "dev", tunIface.Name(), "metric", MetricValue).Run(); err != nil {
		tunIface.Close()
		return nil, "", "", fmt.Errorf("failed to add the default route for the new tun interface: %w", err)
	}

	// VPNサーバーへの例外ルートを追加する。
	vpnIPMask := *svrIP + "/32"
	defaultGateway, err := getDefaultGatewayForInterface(ifaceName)
	if err != nil {
		tunIface.Close()
		return nil, "", "", fmt.Errorf("failed to get default gateway: %w", err)
	}
	if err := exec.Command("ip", "route", "add", vpnIPMask, "via", defaultGateway).Run(); err != nil {
		tunIface.Close()
		return nil, "", "", fmt.Errorf("failed to add routing for the vpn server: %w", err)
	}

	// デフォルトルートをVPNトンネルに向ける
	// プレフィックス長一致の原則を利用し、既存のデフォルトルートを上書きする
	if err := exec.Command("ip", "route", "add", DefaultRouteFirstHalf, "dev", tunIface.Name()).Run(); err != nil {
		tunIface.Close()
		return nil, "", "", fmt.Errorf("failed to add routing the first half of the entire ip address space: %w", err)
	}
	if err := exec.Command("ip", "route", "add", DefaultRouteSecondHalf, "dev", tunIface.Name()).Run(); err != nil {
		tunIface.Close()
		return nil, "", "", fmt.Errorf("failed to add routing the latter half of the entire ip address space: %w", err)
	}

	return tunIface, defaultGateway, vpnIPMask, nil
}

// VPN通信用の通信を追加するために、デフォルトゲートウェイを取得する。
func getDefaultGatewayForInterface(ifaceName string) (string, error) {
	// 指定したインターフェースの情報を取得する
	targetIfaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	targetIfaceLinkIndex := targetIfaceLink.Attrs().Index

	// システム内のルート一覧を取得する。
	// Linuxコマンドの「ip route show」にあたる。
	routeLists, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("failed to get route list: %w", err)
	}

	// デフォルトゲートウェイのIPアドレスを取得する
	for _, routeList := range routeLists {
		if determineDefaultGateway(routeList.Dst) && routeList.Gw != nil && routeList.LinkIndex == targetIfaceLinkIndex {
			return routeList.Gw.String(), nil
		}
	}

	// 対象のインターフェースがない場合の処理
	return "", fmt.Errorf("no default gateway fof target interface %s", ifaceName)
}

// VPN通信で使うインターフェースを選択する。
func selectionLANInterfaceForVPNConnection() (string, error) {
	var selectionIface string

	// VPN通信で使うインターフェースを選択するために、全インターフェースの情報を取得する。
	linkLists, err := netlink.LinkList()
	if err != nil {
		return "", fmt.Errorf("failed to get to all interface infomation: %w", err)
	}

	ifaces := make([]string, len(linkLists))
	fmt.Println()
	for {
		fmt.Println("--------------------------------")
		fmt.Println(" # TLS接続で利用するLANインターフェースを選択してください")
		// 取得してきた利用可能なインターフェースをリスト番号で選択させる。
		for index, linkList := range linkLists {
			ifaces[index] = linkList.Attrs().Name
			fmt.Printf(" [%d] %s\n", index+1, linkList.Attrs().Name)
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
		if err != nil || listValue < 1 || listValue > len(ifaces) {
			fmt.Print("\033c") // CLI画面をクリアにする。
			fmt.Println()
			fmt.Println(" 入力した値は無効な値です")
			fmt.Println(" リスト番号にある番号を入力してください")
			continue
		}
		// 有効なリスト番号が選択された場合、インターフェース名とIPv4アドレスの情報を保持する。
		selectionIface = ifaces[listValue-1]
		return selectionIface, nil
	}
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

// routeLists で取得したルート一覧の宛先（Dst)の判定を行う
func determineDefaultGateway(dst *net.IPNet) bool {
	// 宛先（Dst)が nil の場合の処理
	if dst == nil {
		return true
	}

	// 宛先（Dst)が 0.0.0.0/0 の場合の処理
	// ルーティングエントリの宛先IPアドレスが 0.0.0.0 か確認する。
	// ルーティングエントリのサブネットマスク /0 か確認する。
	dstIP := net.ParseIP("0.0.0.0").To4()
	dstIPMask := net.IPv4Mask(0, 0, 0, 0)
	if dst.IP.Equal(dstIP) && bytes.Equal(dst.Mask, dstIPMask) {
		return true
	}

	return false
}

// TUNデバイスに、任意のDNサーバの割り当てる
func setupDNS(iface *water.Interface) (string, string, error) {
	// 名前解決の情報を管理している管理元を特定し、任意のnameserverを設定する。
	if _, err := exec.LookPath(DNSResolver); err == nil {
		// -------------------------------------------
		// systemd-resolved を使用する処理を実行
		// -------------------------------------------
		// TUNインターフェースに、DNSサーバー(1.1.1.1)を割り当てる
		// 1.1.1.1: プライバシーと速度を重視のDNSサーバ
		if err := exec.Command(DNSResolver, "dns", iface.Name(), *dnsIP).Run(); err != nil {
			return "", "", fmt.Errorf("failed to set dns server on %s: %w", iface.Name(), err)
		}

		// TUNインターフェースをデフォルトのDNS経路に設定する。
		// すべてのドメインの名前解決を行うときは、TUNインターフェースに設定したDNSサーバを使うようにさせる。
		if err := exec.Command(DNSResolver, "domain", iface.Name(), "~.").Run(); err != nil {
			return "", "", fmt.Errorf("failed to set dns domain on %s: %w", iface.Name(), err)
		}

		return "", "", nil
	} else {
		// -------------------------------------------
		// /etc/resolv.conf を使用する処理を実行
		// -------------------------------------------
		var backupPath string
		var originalPath string

		// /etc/resolv.conf がシンボリックリンクかを確認し、操作対象のファイルを確認する。
		symlink, symlinkBool, err := checkSymlink(ResolvConfPath)
		if err != nil {
			return "", "", fmt.Errorf("failed to check resolvconf status: %w", err)
		}

		if symlinkBool {
			// シンボリックリンクが存在する場合、シンボリックリンク元を操作対応とする。
			originalPath = symlink
		} else {
			// シンボリックリンクが存在しない場合、/etc/resolv.conf を操作対応とする。
			originalPath = ResolvConfPath
		}

		// 操作対象のファイルのバックアップを取得する。
		// プログラムの処理終了後に、クリーンアップ処理でバックアップから設定を切り戻すので、バックアップファイル名を返す。
		backupPath = fmt.Sprintf("%s_vpnclient_backup", originalPath)
		if err := exec.Command("cp", "-p", originalPath, backupPath).Run(); err != nil {
			return "", "", fmt.Errorf("failed to copy the %s file: %w", symlink, err)
		}

		// resolv.conf に書き込むNameServerを定義する。
		namesvr := []byte("nameserver" + *dnsIP + "\n")

		// バックアップの取得後に、操作対象のファイルにNameServerを書き換える。
		if err := os.WriteFile(originalPath, namesvr, 0644); err != nil {
			// resolv.conf への書き込みに失敗した場合、バックアップファイルを削除し、バックアップファイルが溜まらないようにする。
			return "", "", fmt.Errorf("failed to write name server the resolv.conf: %w", err)
		}

		return originalPath, backupPath, nil
	}
}

// シンボリックリンクの確認を行う。
func checkSymlink(ResolvConfPath string) (string, bool, error) {
	// resolv.conf のパスがシンボリックリンクであるかを確認する。
	// シンボリックリンクの場合は、シンボリックリンク元のパスを渡す。
	symlink, err := os.Readlink(ResolvConfPath)
	if err == nil {
		return symlink, true, nil
	}

	// os.Readlink でエラー判定された際のエラー判別を行う。
	// 「シンボリックリンクではない」に関するエラーは、正常なエラーとして扱う。
	// それ以外のエラーは、エラーとして扱う。
	// 無効な引数(Invalid)のエラーであるかを確認する。
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, os.ErrInvalid) {
		return "", false, nil
	}

	// 上記の条件分岐で検知できなかった場合のエラーメッセージ検知処理
	// エラーメッセージが「invalid argument」かを確認する。
	if strings.Contains(err.Error(), "invalid argument") {
		return "", false, nil
	}

	// 予期せぬエラー
	return "", false, fmt.Errorf("failed to check symblic link for %s: %w", ResolvConfPath, err)
}

// プログラム終了時に、setupTUN で設定したDNS設定とインターフェース設定を削除する。
func cleanupTUN(tunIface *water.Interface, originalPath, backupPath string) {
	// DNS設定を削除

	//　VPN通信用で作成したTUNインターフェースを削除する。
	if err := cleanupIface(); err != nil {
		log.Printf("%v", err)
	}

	cleanupDNS(tunIface, originalPath, backupPath)
}

func cleanupDefaultRoute(tunIface *water.Interface, defaultGateway string, vpnIPMask string) {
	if err := exec.Command("ip", "route", "delete", vpnIPMask, "via", defaultGateway).Run(); err != nil {
		log.Printf("failed to delete routing for the vpn server")
	}

	// デフォルトルートをVPNトンネルに向ける
	// プレフィックス長一致の原則を利用し、既存のデフォルトルートを上書きする
	if err := exec.Command("ip", "route", "delete", DefaultRouteFirstHalf, "dev", tunIface.Name()).Run(); err != nil {
		log.Printf("failed to delete routing the first half of the entire ip address space")
	}
	if err := exec.Command("ip", "route", "delete", DefaultRouteSecondHalf, "dev", tunIface.Name()).Run(); err != nil {
		log.Printf("failed to delete routing the latter half of the entire ip address space")
	}
}

// カーネル空間に作成したTUNインターフェースを削除する
func cleanupIface() error {
	if err := exec.Command("ip", "link", "delete", *tunName).Run(); err != nil {
		return fmt.Errorf("failed to delete the tun interface %s: %w", *tunName, err)
	}
	return nil
}

// TUNデバイスに、割り当てたDNサーバを削除する。
func cleanupDNS(iface *water.Interface, originalPath, backupPath string) error {
	// 名前解決の情報を管理している管理元を特定し、任意のnameserverを設定する。
	if _, err := exec.LookPath(""); err == nil {
		// -------------------------------------------
		// systemd-resolved を使用する処理を実行
		// -------------------------------------------
		// TUNインターフェースをデフォルトのDNS経路に設定する。
		// すべてのドメインの名前解決を行うときは、TUNインターフェースに設定したDNSサーバを使うようにさせる。
		if err := exec.Command(DNSResolver, "domain", iface.Name(), "").Run(); err != nil {
			return fmt.Errorf("failed to unset dns domain on %s: %w", iface.Name(), err)
		}

		// TUNインターフェースに、DNSサーバー(1.1.1.1)を割り当てる
		// 1.1.1.1: プライバシーと速度を重視のDNSサーバ
		if err := exec.Command(DNSResolver, "dns", iface.Name(), "").Run(); err != nil {
			return fmt.Errorf("%s: %w", iface.Name(), err)
		}

		return nil
	} else {
		// -------------------------------------------
		// /etc/resolv.conf を使用する処理を実行
		// -------------------------------------------
		// バックアップファイルを元のファイルに名前を変更する
		// これにより、setupDNS で書き換えた元のファイルを書き換える前に戻す
		if err := os.Rename(backupPath, originalPath); err != nil {
			return fmt.Errorf("failed to restore backup file from %s to %s :%w", backupPath, originalPath, err)
		}
		return nil
	}
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

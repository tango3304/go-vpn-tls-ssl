### ビルド方法
go build -o [NewFileName] vpn_client.go  
go build -o [NewFileName] vpn_server.go  

[NewFileName] には、新しく作成するファイルに任意の名前をつける。  
実行例：go build -o vpnClient vpn_client.go  
<br></br>

### VPNサーバ側のオプション
**※ root権限で実行が必要  
先にサーバ側を実行し、VPN通信用のポートを開放する。  
ポートを開放せずにクライアント側を実行してもポート開放に関するエラーで正常に実行されない。**  

実行例：  
ビルドあり：sudo ./vpnClient -tun-name vpn1  
ビルドなし：sudo go run vpn_client.go -tun-name vpn1  
| 項目名 | オプション | 実行例 | デフォルト値 |
| ------|---------|----| -----------|
| TUNインターフェースの名前 | -tun-name xxx | -tun-name vpn1 | vpn0 |
| TUNインターフェースのIPアドレス | -tun-ip xxx.xxx.xxx.xxx/xx | -tun-ip 10.10.10.2/24 | 10.0.0.46/24 |
| VPN通信に利用するポート番号 | -port xxxx | -port 18563 | 4433 |

<br><br/>
### VPNクライアント側のオプション
**※ root権限で実行が必要**  

実行例：  
ビルドあり：sudo ./vpnClient -server-ip 192.168.1.1  
ビルドなし：sudo go run vpn_client.go -server-ip 192.168.1.1
| 項目名 | オプション | 例 | デフォルト値 |
| ------|---------|----| -----------|
| VPNサーバのIPアドレス（**この設定は必須**）| -server-ip xxx.xxx.xxx.xxx | -server-ip 192.168.1.1 | ー |
| TUNインターフェースの名前 | -tun-name xxx | -tun-name vpn1 | vpn0|
| VPN通信に利用するポート番号 | -port xxx | -port 18563 | 4433 |
| 名前解決先のDNSサーバのIPアドレス | -dns-ip x.x.x.x | -dns-ip 8.8.8.8 | 1.1.1.1|




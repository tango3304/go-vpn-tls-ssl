## VPNクライアント側のオプション
| 項目名 | コマンド | 例 | デフォルト値 |
| ------|---------|----| -----------|
| VPNサーバのIPアドレス（**この設定は必須**）| -server-ip xxx.xxx.xxx.xxx | -server-ip 192.168.1.1 | ー |
| TUNインターフェースの名前 | -tun-name xxx | -tun-name vpn1 | vpn0|
| VPN通信に利用するポート番号 | -port xxx | -port 18563 | 4433 |
| 名前解決先のDNSサーバのIPアドレス | -dns-ip x.x.x.x | -dns-ip 8.8.8.8 | 1.1.1.1|

<br></br>
## VPNサーバ側のオプション
| 項目名 | コマンド | 例 | デフォルト値 |
| ------|---------|----| -----------|
| TUNインターフェースの名前 | -tun-name xxx | -tun-name vpn1 | vpn0 |
| TUNインターフェースのIPアドレス | -tun-ip xxx.xxx.xxx.xxx/xx | -tun-ip 10.10.10.2/24 | 10.0.0.46/24 |
| VPN通信に利用するポート番号 | -port xxxx | -port 18563 | 4433 |

## VPNクライアント側のオプション
| 項目名 | コマンド | 例文 |
| ------|---------|------|
| VPNサーバのIPアドレス（**この設定は必須**）| -server-ip xxx.xxx.xxx.xxx | -server-ip 192.168.1.1 |
| TUNインターフェースの名前 | -tun-name xxx | -tun-name vpn0 |
| VPN通信に利用するポート番号 | -port xxx | -port 4433 |
| 名前解決先のDNSサーバのIPアドレス | -dns-ip x.x.x.x | -dns-ip 1.1.1.1 |

<br></br>
## VPNサーバ側のオプション
| 項目名 | コマンド | 例文 |
| ------|---------|------|
| TUNインターフェースの名前 | -tun-name xxx | -tun-name vpn0 |
| TUNインターフェースのIPアドレス | -tun-ip xxx.xxx.xxx.xxx/xx | -tun-ip 10.0.0.46/24 |
| VPN通信に利用するポート番号 | -port xxxx | -port 4433 |

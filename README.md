# VPS Tunnel Tool

OpenVPNで接続した別拠点PCのサービスを、VPSの公開ポートやHTTPSサブドメインから公開するための管理WebUIです。

## 主な機能

- Easy-RSAによるOpenVPNクライアント証明書と埋め込み済み `.ovpn` の発行
- `VPSのポート -> VPN接続先IP:ポート` のTCP/UDP転送ルール管理
- nftablesルールの生成・反映とsystemdによる再起動時の再適用
- 有効なnginx設定から割り当て済みURLを自動検出
- WebUIからnginx vhostを作成し、DNS反映済みならLet's EncryptでHTTPS化
- 公開ルールの検索、状態・プロトコル・URL割当状況による絞り込み

## 構成

```text
Internet
   |
   +-- VPS public port -- nftables DNAT -- OpenVPN -- private service
   |
   +-- HTTPS domain ---- nginx ----------- OpenVPN -- private web service
```

## 必要環境

- Ubuntu系Linuxとroot権限
- Python 3.10以上
- OpenVPNサーバー
- Easy-RSA PKI（既定: `/etc/openvpn/easy-rsa/pki`）
- nftables
- nginxとcertbot（URL割当・HTTPS機能を使う場合）

## 新しいサーバーへの導入

```bash
sudo apt update
sudo apt install -y python3 python3-venv openvpn easy-rsa nftables nginx certbot python3-certbot-nginx

sudo git clone https://github.com/server031x-del/vps-tunnel-tool.git /opt/vps-tunnel-tool
cd /opt/vps-tunnel-tool
sudo python3 -m venv .venv
sudo .venv/bin/pip install -e .
```

環境変数ファイルを作成します。実値をGitへコミットしないでください。

```bash
sudo cp .env.example /etc/vps-tunnel-tool.env
sudo chmod 600 /etc/vps-tunnel-tool.env
sudo editor /etc/vps-tunnel-tool.env
```

`VPS_TUNNEL_TOOL_SECRET` は次のように生成できます。

```bash
openssl rand -hex 32
```

初期化とsystemd登録:

```bash
cd /opt/vps-tunnel-tool
sudo .venv/bin/python main.py init
sudo cp deploy/vps-tunnel-tool-web.service.example /etc/systemd/system/vps-tunnel-tool-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now vps-tunnel-tool-web.service
```

WebUIは安全のため `127.0.0.1:5000` だけで待ち受けます。外部公開はnginxのHTTPSリバースプロキシと認証を経由させてください。
基本形は [`deploy/nginx-admin.conf.example`](deploy/nginx-admin.conf.example) を参照してください。

## CLI

```bash
sudo -E .venv/bin/python main.py init
sudo -E .venv/bin/python main.py apply
sudo -E .venv/bin/python main.py install-systemd
sudo -E .venv/bin/python main.py install-web-systemd --host 127.0.0.1 --port 5000
```

## 実データの保存場所

以下は `.gitignore` の対象です。

- SQLite DB: `app/data/app.db`
- OpenVPNクライアントプロファイル: `app/data/exports/`
- 生成済みnftablesルール: `app/data/generated/`
- ローカル環境変数ファイル: `.env`、`*.env`
- 秘密鍵・証明書・`.ovpn` ファイル

バックアップや別サーバーへの移行時も、これらは公開Gitリポジトリではなく暗号化された安全な経路で移してください。

## セキュリティ上の注意

- WebUIをFlask開発サーバーのポートで直接インターネット公開しないでください。
- 強いアプリログインパスワードを設定し、nginx側にも認証や接続元制限を追加してください。
- URL割当機能はroot権限でnginx設定とcertbotを操作します。管理画面へのアクセスを厳しく制限してください。
- SMBの `445/tcp` など高リスクなサービスを無制限に公開しないでください。
- `.ovpn` にはクライアント秘密鍵が含まれるため、Gitへ追加しないでください。

## テスト

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile main.py app/*.py tests/*.py
```

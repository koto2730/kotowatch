# kotowatch

**kotowatch** は、PC上で実行されるプロセス・コマンドライン引数、外部とのネットワーク通信・DNS名前解決、およびファイル操作をリアルタイムに監視し、不審な挙動（EDR / HIDS 相当の検知ルール）をターミナルへ即座に通知する軽量セキュリティ監視ツールです。

> **【作成の背景と免責事項（ご注意）】**
> - 本ツールは、昨今の不正アクセスに関するニュースを目にしたことをきっかけに、「自分のPCの中で普段どのようなプロセスや通信が動いているのか、怪しい挙動を検知できるのか」を試す目的で作成してもらった実験的・学習用アプリケーションです。
> - **商用・本格的なセキュリティ製品としての品質、網羅性、完全な検知精度、および安全性を保証するものではありません。**
> - 実際のマルウェアや高度な攻撃をすべて防げるものではなく、誤検知や検知漏れが発生する可能性があります。あくまで挙動観察や学習・参考用途として、自己責任にてご利用ください。

---

## 主な特徴

- **フルコマンドラインと親子関係の特定**: 起動されたプロセスの実行ファイルパス、フルコマンドライン引数、親プロセス（PPID / 親プロセス名）、実行ユーザーを即座に取得します。
- **プロセスと通信・ファイル操作の紐付け**: 「どのプロセス（どのコマンド）が怪しい外部サーバと通信したか」「どのプロセスがファイルを削除・書き換えしたか」を紐付けて表示します。
- **OS別ハイブリッド監視エンジン（Windows / macOS / Linux 対応）**:
  - **Windows**: **ETW (Event Tracing for Windows)** カーネルトレース（`Kernel-Process`, `DNS-Client`, `Kernel-Network`, `Kernel-File`）＋ `fsnotify`（非管理者時はプロセス差分＋TCP拡張テーブルへ自動フォールバック）。
  - **macOS**: **Endpoint Security (`eslogger`)** カーネルイベントストリーム（root実行時）＋ `ps` / `lsof` / BSD `kqueue` (`fsnotify`) によるリアルタイム監視。起動時に `rules.macos.yaml` を自動選択します。
  - **Linux**: **`/proc/net/tcp` + `/proc/<pid>/fd`** ソケットinode直接解析（`lsof` がない最小構成サーバでも動作）＋ `ps` / Linux `inotify` (`fsnotify`) によるリアルタイム監視。起動時に `rules.linux.yaml` を自動選択します。
- **YAMLによる柔軟なルール設定**: コードを再ビルドすることなく、`rules.yaml`（Windows用）、`rules.macos.yaml`（macOS用）、`rules.linux.yaml`（Linux用）を編集するだけで監視対象フォルダや検知ルールを自在にカスタマイズできます。

---

## ビルド済みパッケージ（`build/` フォルダ構成）

各OS向けにビルドされた実行ファイルと対応するルール定義ファイルは `build/` 配下のOS別フォルダに格納されています。各OSフォルダごと配布・コピーしてすぐに実行できます。

```text
build/
├── windows/
│   ├── kotowatch.exe         # Windows (x64 / amd64) 実行ファイル
│   └── rules.yaml            # Windows用 標準20ルール設定
├── macos/
│   ├── kotowatch             # macOS デフォルト実行ファイル (Apple Silicon arm64)
│   ├── kotowatch-arm64       # macOS Apple Silicon (M1/M2/M3/M4) 用
│   ├── kotowatch-amd64       # macOS Intel (x86_64) 用
│   ├── rules.yaml            # macOS用 標準20ルール設定
│   └── rules.macos.yaml      # macOS用 標準20ルール設定（明示名）
└── linux/
    ├── kotowatch             # Linux デフォルト実行ファイル (x86_64 / amd64)
    ├── kotowatch-amd64       # Linux x86_64 (amd64) 用
    ├── kotowatch-arm64       # Linux ARM64 (AWS Graviton / Raspberry Pi等) 用
    ├── rules.yaml            # Linux用 標準20ルール設定
    └── rules.linux.yaml      # Linux用 標準20ルール設定（明示名）
```

---

## ビルドと実行方法

### 1. ソースからのビルド（各OSでのビルド & クロスコンパイル対応）

Go 1.22 以上（Go 1.27 動作確認済）でシングルバイナリとしてビルドできます（CGO不要）。

#### Windows (PowerShell) 上でビルドする場合
```powershell
# Windows (amd64) 向けビルド
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -o build/windows/kotowatch.exe .

# macOS Apple Silicon (arm64) / Intel (amd64) 向けビルド
$env:GOOS="darwin"; $env:GOARCH="arm64"; go build -o build/macos/kotowatch-arm64 .
$env:GOOS="darwin"; $env:GOARCH="amd64"; go build -o build/macos/kotowatch-amd64 .

# Linux x86_64 (amd64) / ARM64 (arm64) 向けビルド
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o build/linux/kotowatch-amd64 .
$env:GOOS="linux"; $env:GOARCH="arm64"; go build -o build/linux/kotowatch-arm64 .
```

#### macOS / Linux (bash / zsh) 上でビルドする場合
```bash
# 現在のOS向けにそのままビルドする場合
go build -o kotowatch .

# 各OS向けにクロスビルドする場合
GOOS=windows GOARCH=amd64 go build -o build/windows/kotowatch.exe .
GOOS=darwin  GOARCH=arm64 go build -o build/macos/kotowatch-arm64 .
GOOS=darwin  GOARCH=amd64 go build -o build/macos/kotowatch-amd64 .
GOOS=linux   GOARCH=amd64 go build -o build/linux/kotowatch-amd64 .
GOOS=linux   GOARCH=arm64 go build -o build/linux/kotowatch-arm64 .
```

### 2. 実行コマンドとオプション

#### Windows の場合 (`build/windows/`)
```powershell
cd build\windows

# 1. 通常運用モード（ルールに一致した怪しい動き [ALERT] のみを表示）
.\kotowatch.exe

# 2. リアルタイム観察モード（PC内で起きている全プロセス・通信・ファイル操作もすべて表示）
.\kotowatch.exe -v

# 3. 管理者権限（UAC昇格）で別ウィンドウ起動（ETWカーネル監視のフル機能を有効化）
.\kotowatch.exe -v --elevate
```

#### macOS の場合 (`build/macos/`)
```bash
cd build/macos
chmod +x ./kotowatch

# 1. リアルタイム観察モード（sudoでシステム全体 + Endpoint Security監視を有効化）
sudo ./kotowatch -v

# 2. 一般ユーザー権限で手軽に動作確認する場合
./kotowatch -v
```
> **macOS でのヒント**: macOS 13 以降で `sudo` 実行時に Apple Endpoint Security (`eslogger`) によるカーネルイベント監視を有効化する場合は、「システム設定 > プライバシーとセキュリティ > フルディスクアクセス」でお使いのターミナル（Terminal.app / iTerm2 等）を許可しておくと、より詳細なイベントが取得できます。

#### Linux の場合 (`build/linux/`)
```bash
cd build/linux
chmod +x ./kotowatch

# 1. リアルタイム観察モード（sudoで全ユーザーのプロセス・ソケットinodeの紐付けを有効化）
sudo ./kotowatch -v

# 2. 通常運用モード（アラートのみ表示）
sudo ./kotowatch
```

| フラグ | 説明 |
| :--- | :--- |
| `-v`, `--watch-all` | アラートだけでなく、通常のプロセス起動 (`[PROC]`)・通信 (`[NET]`)・DNS (`[DNS]`)・ファイル操作 (`[FILE]`) もすべてリアルタイム表示します。 |
| `--config <path>` | ルール定義YAMLファイルのパスを指定します（デフォルト: `rules.yaml`）。 |
| `--elevate` | 非管理者ターミナルから実行した際、UACダイアログを表示して管理者権限のコンソールで再起動します。 |
| `--duration <time>` | 指定時間（例: `15s`, `5m`）だけ監視を実行して自動終了します（省略または `0` で無制限）。 |

---

## 出力サンプル

```text
[03:53:33.886] [PROC] PID:38668  git.exe          (Parent: ChatGPT.exe:2196) | Cmd: "C:\Program Files\Git\cmd\git.exe" ...
[03:53:49.095] [NET ] PID:32016  eServiceHost.exe | CONNECT 100.90.126.159:51740 -> 91.228.167.200:443

[ALERT] 2026-10-25 03:53:32.635 | Severity: MEDIUM | Rule: command_file_deletion
  Message : コマンドによるファイル削除（del / Remove-Item / shadow copy削除）を検知
  Process : cmd.exe (PID: 22836 / Parent: powershell.exe (28608))
  User    : DESKTOP\User
  Command : "C:\Windows\system32\cmd.exe" /c "del C:\Users\User\Documents\sample_target.txt"

[ALERT] 2026-10-25 03:53:50.096 | Severity: HIGH | Rule: shell_outbound_connection
  Message : シェルやスクリプトエンジンからの外部サーバ通信を検知
  Process : curl.exe (PID: 20280 / Parent: powershell.exe (8084))
  User    : DESKTOP\User
  Command : "C:\Windows\system32\curl.exe" -s https://example.com
  Network : [OUTBOUND] 100.90.126.159:51745 -> 172.66.147.243:443
```

---

## `rules.yaml` で指定できる全監視条件（機能リファレンス）

`rules.yaml` では、`type`（`process` / `network` / `dns` / `file`）ごとに以下の条件フィールドを組み合わせて指定できます。

| カテゴリ | フィールド名 | 監視・判定できる内容 |
| :--- | :--- | :--- |
| **共通 / プロセス**<br>(`type: process`) | `process_names` | 実行ファイル名（例: `powershell.exe`, `cmd.exe`） |
| | `exclude_process_names` | 除外するプロセス名（誤検知防止用のホワイトリスト） |
| | `parent_names` | **親プロセス名**（例: `WINWORD.EXE` や `sshd.exe` から起動されたかを判定） |
| | `exe_path_contains` | **実行ファイルの配置パス**（例: `Temp` や `Public` フォルダからの直接実行を検知） |
| | `command_contains` | コマンドライン引数の部分一致（いずれか1つを含めば一致：OR条件） |
| | `command_all` | コマンドライン引数の複数必須一致（すべて含めば一致：AND条件） |
| | `exclude_command_contains` | 除外するコマンドライン引数 |
| | `users_contain` | 実行ユーザー名（例: `SYSTEM` や特定アカウント） |
| **ネットワーク / DNS**<br>(`type: network` / `dns`) | `direction` | 通信の向き（`inbound`: 外部からの着信 / `outbound`: 外部への発信） |
| | `local_ports` | 自端末側のポート番号（例: RDP `3389`, SSH `22` への着信） |
| | `remote_ports` | 接続先サーバのポート番号（例: バックドア `4444`, マイニング `3333`） |
| | `remote_ips_contain` | 接続先IPアドレス・サブネットの部分一致 |
| | `domains_contain` | **DNS名前解決・接続先ドメイン名**（例: `ngrok`, `.onion`, `pastebin.com`） |
| **ファイル操作**<br>(`type: file`) | `actions` | 操作種別（`CREATE`: 作成, `WRITE`: 書き換え, `DELETE`: 削除, `RENAME`: 名前変更） |
| | `path_contains` | 対象ファイルパスの部分一致（例: `hosts`, `.ssh\`, `.env`） |
| | `exclude_path_contains` | 除外するファイルパス |
| | `extensions` | **対象ファイルの拡張子**（例: `.exe`, `.ps1`, `.bat`, `.dll` の新規配置検知） |

---

## 標準搭載ルール一覧（全20ルール）

デフォルトの `rules.yaml` には、MITRE ATT&CK の主要フェーズを網羅した以下の20ルールが定義されています。

### 1. プロセス・コマンドライン監視（12ルール）

| # | ルールID | 重要度 | 検知内容 |
| :--- | :--- | :--- | :--- |
| 1 | `suspicious_powershell` | HIGH | PowerShell の難読化（`-enc`）、非表示実行（`-w hidden`）、外部コード取得（`DownloadString`, `IEX` 等） |
| 2 | `exec_from_suspicious_path` | HIGH | 一時フォルダ（`\AppData\Local\Temp\`）や `\Users\Public\` 等からのプログラム直接実行 |
| 3 | `app_spawn_shell` | CRITICAL | Office製品（Word/Excel/Outlook）やPDFリーダーからの不審なシェル起動（マクロ・エクスプロイト検知） |
| 4 | `remote_service_spawn_shell` | CRITICAL | `sshd.exe`, `wsmprovhost.exe`（WinRM）, `wmiprvse.exe`（WMI）からのシェル起動 |
| 5 | `command_file_deletion` | MEDIUM | `del`, `erase`, `Remove-Item`, `rmdir /s`, `cipher /w:` によるファイル消去コマンド |
| 6 | `ransomware_shadowcopy_deletion` | CRITICAL | `vssadmin delete shadows` や `bcdedit` によるバックアップ（シャドウコピー）・復旧機能の破壊 |
| 7 | `persistence_creation` | HIGH | `schtasks /create`, `sc create`, レジストリ `CurrentVersion\Run` への自動起動（永続化）登録 |
| 8 | `credential_access_commands` | CRITICAL | `reg save hklm\sam`, `mimikatz`, `procdump`, `comsvcs.dll MiniDump`, `cmdkey /list` 等の認証情報窃取 |
| 9 | `defense_evasion_commands` | CRITICAL | Windows Defender 無効化（`DisableRealtimeMonitoring`）、ファイアウォール解除、イベントログ消去（`wevtutil cl`） |
| 10 | `lolbin_abuse` | HIGH | OS標準ツール悪用（`certutil -urlcache`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32 javascript:`） |
| 11 | `account_manipulation` | CRITICAL | `net user /add` や `localgroup administrators` による不正アカウント作成・管理者権限昇格 |
| 12 | `recon_and_account_commands` | LOW | `whoami`, `net`, `nltest`, `quser`, `systeminfo`, `arp` 等の端末内偵察コマンド |

### 2. ネットワーク・DNS監視（5ルール）

| # | ルールID | 重要度 | 検知内容 |
| :--- | :--- | :--- | :--- |
| 13 | `inbound_remote_access` | HIGH | 外部からのリモート接続着信（RDP `3389`, SSH `22`, Telnet `23`, SMB `445`, VNC `5900`, WinRM `5985`/`5986`） |
| 14 | `shell_outbound_connection` | HIGH | シェルやスクリプトエンジン（`powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe` 等）からの外部サーバ通信 |
| 15 | `cli_transfer_outbound` | MEDIUM | CLI通信ツール（`curl.exe`, `ssh.exe`, `scp.exe`, `ftp.exe`, `nc.exe` 等）による外部への接続・データ転送 |
| 16 | `suspicious_remote_port` | CRITICAL | C2・バックドア・マイニング・Tor等で多用されるポート（`4444`, `1337`, `3333`, `5555`, `6667`, `9001`, `9050`）への外向き通信 |
| 17 | `suspicious_tunnel_or_paste_domain` | HIGH | トンネルサービス（`ngrok`, `trycloudflare.com`）やペーストサイト（`pastebin.com`, `webhook.site`）、`.onion` 等の名前解決・通信 |

### 3. ファイル操作監視（3ルール）

| # | ルールID | 重要度 | 検知内容 |
| :--- | :--- | :--- | :--- |
| 18 | `file_deleted_in_watched_dir` | HIGH | 監視対象フォルダ内でのファイル削除（`DELETE`） |
| 19 | `executable_or_script_dropped` | HIGH | 監視対象フォルダへの実行ファイル・スクリプト（`.exe`, `.dll`, `.ps1`, `.bat`, `.vbs` 等）の新規作成・書き換え |
| 20 | `critical_system_file_modified` | CRITICAL | `hosts` ファイル、スタートアップフォルダ、SSH鍵（`.ssh\`, `id_rsa`, `authorized_keys`）、`.env`、`.kdbx` の作成・変更・削除・リネーム |

---

## macOS 専用ルール一覧（`rules.macos.yaml` 全20ルール）

macOS 版（`rules.macos.yaml`）では、macOS 特有の機構（`osascript` / AppleScript、Gatekeeper検疫属性 `com.apple.quarantine`、`LaunchAgents` / `LaunchDaemons`、キーチェーン `security`、Time Machine `tmutil` 等）に合わせた20ルールを定義しています。

| # | ルールID | 重要度 | 検知内容（macOS） |
| :--- | :--- | :--- | :--- |
| 1 | `suspicious_shell_execution` | HIGH | `zsh` / `bash` / `sh` による Base64 デコード（`base64 -D`）や `curl ... \| sh` パイプ実行 |
| 2 | `suspicious_osascript` | HIGH | `osascript`（AppleScript/JXA）による `do shell script` やパスワード入力ダイアログ偽装 |
| 3 | `gatekeeper_quarantine_bypass` | HIGH | `xattr -d com.apple.quarantine` による検疫属性削除や `spctl --master-disable`（Gatekeeper無効化） |
| 4 | `exec_from_suspicious_path` | HIGH | `/tmp/`, `/var/tmp/`, `/Users/Shared/` からの直接プログラム実行 |
| 5 | `app_spawn_shell` | CRITICAL | Office for Mac や Preview からの不審なシェル・`osascript` 起動 |
| 6 | `remote_service_spawn_shell` | CRITICAL | `sshd` 等のリモートサービスからのシェル起動 |
| 7 | `command_file_deletion` | MEDIUM | `rm -rf`, `rm -f`, `srm`, `find -delete` によるファイル削除コマンド |
| 8 | `timemachine_snapshot_deletion` | CRITICAL | `tmutil deletelocalsnapshots` や `tmutil disable` による Time Machine バックアップ削除 |
| 9 | `persistence_creation` | HIGH | `launchctl load/bootstrap`, `crontab`, `LaunchAgents`, `LoginHook` による自動起動登録 |
| 10 | `credential_keychain_access` | CRITICAL | `security find-generic-password` や `security dump-keychain` によるキーチェーン窃取 |
| 11 | `defense_evasion_commands` | CRITICAL | `socketfilterfw`（Firewall解除）、`tccutil reset`（TCCリセット）、`log erase`（ログ消去） |
| 12 | `recon_and_account_commands` | LOW | `whoami`, `id`, `dscl`, `dscacheutil`, `scutil`, `sw_vers`, `arp`, `last` 等の内部偵察 |
| 13 | `inbound_remote_access` | HIGH | 外部からのリモート接続着信（SSH `22`, SMB `445`, Apple Remote Desktop `3283`, 画面共有VNC `5900`） |
| 14 | `shell_outbound_connection` | HIGH | `zsh`, `bash`, `osascript`, `python3`, `ruby`, `perl` からの外部サーバ通信 |
| 15 | `cli_transfer_outbound` | MEDIUM | `curl`, `wget`, `ssh`, `scp`, `sftp`, `nc`, `socat` による外部接続 |
| 16 | `suspicious_remote_port` | CRITICAL | 不審な宛先ポート（`1337`, `3333`, `4444`, `5555`, `6667`, `9001`, `9050`）への外向き通信 |
| 17 | `suspicious_tunnel_or_paste_domain` | HIGH | `ngrok`, `trycloudflare.com`, `pastebin.com`, `webhook.site`, `duckdns.org`, `.onion` 等への通信 |
| 18 | `file_deleted_in_watched_dir` | HIGH | 監視対象フォルダ内でのファイル削除（`DELETE`） |
| 19 | `executable_or_script_dropped` | HIGH | 監視対象フォルダへの `.sh`, `.zsh`, `.command`, `.scpt`, `.pkg`, `.dmg`, `.dylib`, `.plist` 等の新規配置 |
| 20 | `critical_system_file_modified` | CRITICAL | `LaunchAgents` / `LaunchDaemons`、`/etc/hosts`、`/etc/sudoers`、`~/.ssh/`、`~/.zshrc`、`.env` の変更 |

---

## Linux 専用ルール一覧（`rules.linux.yaml` 全20ルール）

Linux 版（`rules.linux.yaml`）では、Linux サーバ・デスクトップ特有の脅威（`/dev/tcp/` や `nc -e` によるリバースシェル、SUID昇格 `chmod +s`、`/dev/shm` 共有メモリ実行、Webサーバからのシェル起動、カーネルモジュール `insmod`、`LD_PRELOAD`、`/etc/shadow` 窃取、`ufw`/`iptables`/`auditd` 停止等）に合わせた20ルールを定義しています。

| # | ルールID | 重要度 | 検知内容（Linux） |
| :--- | :--- | :--- | :--- |
| 1 | `suspicious_shell_execution` | HIGH | `bash` / `sh` / `dash` による Base64 デコード（`base64 -d`）、`curl \| sh`、`/dev/tcp/` 通信 |
| 2 | `reverse_shell_commands` | CRITICAL | リバースシェル定番コマンド（`nc -e /bin/`, `mkfifo`, `socat exec:`, `python import pty` 等） |
| 3 | `privilege_escalation_suid` | CRITICAL | SUIDビット付与（`chmod +s`, `chmod 4755`）や特権・名前空間操作（`pkexec`, `nsenter`, `capsh`） |
| 4 | `exec_from_suspicious_path` | HIGH | `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/shm/` からの直接バイナリ実行 |
| 5 | `server_spawn_shell` | CRITICAL | WebサーバやDB（`nginx`, `apache2`, `php-fpm`, `java`, `node`, `postgres`, `redis-server`）からのシェル起動 |
| 6 | `remote_service_spawn_shell` | HIGH | `sshd` 等のリモートサービスからのシェル起動 |
| 7 | `command_file_deletion` | MEDIUM | `rm -rf`, `rm -f`, `shred`, `wipe`, `find -delete` によるファイル削除・完全抹消コマンド |
| 8 | `kernel_module_or_preload_abuse` | CRITICAL | カーネルモジュール操作（`insmod`, `modprobe`, `rmmod`）や `LD_PRELOAD` / `ld.so.preload` 悪用 |
| 9 | `persistence_creation` | HIGH | `crontab`, `systemctl enable`, `/etc/rc.local` による自動起動（永続化）登録 |
| 10 | `credential_shadow_access` | CRITICAL | `/etc/shadow`, `/etc/gshadow` の読み取りや `unshadow`, `hashcat`, `john` の実行 |
| 11 | `defense_evasion_commands` | CRITICAL | `ufw disable`, `iptables -F`, `setenforce 0`, `auditd stop`, `history -c`, `/var/log` 消去 |
| 12 | `recon_and_account_commands` | LOW | `whoami`, `id`, `uname`, `last`, `who`, `w`, `arp`, `netstat`, `ss` 等の内部偵察 |
| 13 | `inbound_remote_access` | HIGH | 外部からのリモート接続着信（SSH `22`, Telnet `23`, SMB `445`, Docker API `2375`/`2376`, VNC `5900`, Redis `6379`, Kubelet `10250`） |
| 14 | `shell_outbound_connection` | HIGH | `bash`, `sh`, `dash`, `python3`, `perl`, `ruby`, `php`, `lua` からの外部サーバ通信 |
| 15 | `cli_transfer_outbound` | MEDIUM | `curl`, `wget`, `ssh`, `scp`, `rsync`, `nc`, `ncat`, `socat`, `ftp`, `tftp` による外部接続 |
| 16 | `suspicious_remote_port` | CRITICAL | 不審な宛先ポート（`1337`, `3333`, `4444`, `5555`, `6667`, `9001`, `9050`）への外向き通信 |
| 17 | `suspicious_tunnel_or_paste_domain` | HIGH | `ngrok`, `trycloudflare.com`, `pastebin.com`, `webhook.site`, `duckdns.org`, `.onion` 等への通信 |
| 18 | `file_deleted_in_watched_dir` | HIGH | 監視対象フォルダ内でのファイル削除（`DELETE`） |
| 19 | `executable_or_script_dropped` | HIGH | 監視対象フォルダへの `.sh`, `.py`, `.so`（共有ライブラリ）, `.ko`（カーネルモジュール）, `.service` 等の新規配置 |
| 20 | `critical_system_file_modified` | CRITICAL | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ld.so.preload`, `/etc/systemd/system/`, `.ssh/`, `.bashrc` 等の変更 |

---

## ディレクトリ構成

```text
kotowatch/
├── main.go                             # CLIエントリポイント・ターミナル出力制御
├── platform_windows.go                 # Windows固有のコンソール・UAC昇格処理
├── platform_unix.go                    # macOS / Linux 固有の設定選択・sudo昇格処理
├── rules.yaml                          # Windows用 監視パス・全20検知ルール定義
├── rules.macos.yaml                    # macOS用 監視パス・全20検知ルール定義
├── rules.linux.yaml                    # Linux用 監視パス・全20検知ルール定義
├── build/                              # リリース・配布用OS別ビルド成果物
│   ├── windows/                        # Windows (kotowatch.exe + rules.yaml)
│   ├── macos/                          # macOS (kotowatch[arm64/amd64] + rules.yaml)
│   └── linux/                          # Linux (kotowatch[amd64/arm64] + rules.yaml)
└── internal/
    ├── model/
    │   └── event.go                    # OS非依存のイベント・アラート構造体
    ├── config/
    │   └── config.go                   # YAMLルール読み込み・環境変数(~ / %VAR% / $VAR)展開
    ├── detector/
    │   └── detector.go                 # ルールマッチングエンジン
    ├── procstore/
    │   ├── store_windows.go            # Windows プロセス情報・コマンドライン取得・DNSキャッシュ
    │   └── store_unix.go               # macOS / Linux プロセス情報・コマンドライン取得
    └── collector/
        ├── collector.go                # OS別コレクターの共通インターフェース
        ├── etw_windows.go              # Windows ETW カーネルイベント監視実装
        ├── collector_windows.go        # Windows ファイル監視(fsnotify)・フォールバック監視実装
        └── collector_unix.go           # macOS (eslogger/lsof/kqueue) & Linux (/proc/net/tcp + inotify) 監視実装
```

---

## ライセンス (License)

本プロジェクトは [MIT License](LICENSE) の下で公開されています。


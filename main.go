package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"kotowatch/internal/collector"
	"kotowatch/internal/config"
	"kotowatch/internal/detector"
	"kotowatch/internal/model"
	"kotowatch/internal/procstore"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31;1m"
	colorYellow = "\033[33;1m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorGray   = "\033[90m"
)

func main() {
	configPath := flag.String("config", defaultConfigPath(), "監視ルール設定ファイル(YAML)のパス")
	watchAll := flag.Bool("watch-all", false, "通常イベント（全プロセス起動・通信・ファイル操作）もすべてリアルタイム表示する")
	flag.BoolVar(watchAll, "v", false, "--watch-all の短縮フラグ")
	duration := flag.Duration("duration", 0, "指定時間だけ実行して自動終了する（例: 15s, 0=無制限）")
	elevate := flag.Bool("elevate", false, "管理者権限(Windows:UAC / macOS,Linux:sudo)へ昇格して起動する")
	flag.Parse()

	enableANSI()

	if *elevate && !procstore.IsAdmin() {
		if err := relaunchAsAdmin(); err != nil {
			fmt.Fprintf(os.Stderr, "%s[ERROR] 管理者権限への昇格に失敗しました: %v%s\n", colorRed, err, colorReset)
			os.Exit(1)
		}
		fmt.Printf("%s[INFO] 管理者権限で kotowatch を起動しました。%s\n", colorGreen, colorReset)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[ERROR] 設定ファイル (%s) の読み込みに失敗しました: %v%s\n", colorRed, *configPath, err, colorReset)
		os.Exit(1)
	}

	store := procstore.NewStore()
	det := detector.New(cfg.Rules)
	col := collector.New(store, cfg.WatchPaths)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *duration > 0 {
		var timeCancel context.CancelFunc
		ctx, timeCancel = context.WithTimeout(ctx, *duration)
		defer timeCancel()
	}

	events := make(chan model.Event, 1024)
	if err := col.Start(ctx, events); err != nil {
		fmt.Fprintf(os.Stderr, "%s[ERROR] コレクターの起動に失敗しました: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}

	printBanner(*configPath, cfg, col.Mode(), *watchAll)

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\n%s[INFO] kotowatch を終了しました。%s\n", colorGreen, colorReset)
			return
		case ev := <-events:
			alerts := det.Evaluate(ev)
			if len(alerts) > 0 {
				for _, a := range alerts {
					printAlert(a)
				}
			} else if *watchAll {
				printEvent(ev)
			}
		}
	}
}

func printBanner(cfgPath string, cfg *config.Config, mode string, watchAll bool) {
	adminStatus := fmt.Sprintf("%sTRUE (システム全体監視有効)%s", colorGreen, colorReset)
	if !procstore.IsAdmin() {
		hint := "管理者ターミナルで実行または --elevate を付与"
		if runtime.GOOS != "windows" {
			hint = "sudo ./kotowatch または --elevate を付与"
		}
		adminStatus = fmt.Sprintf("%sFALSE (ユーザーモード監視 / フル機能を使うには %s)%s", colorYellow, hint, colorReset)
	}

	modeDisplay := "アラート検知のみ（通常イベントもすべて見るには -v または --watch-all を指定）"
	if watchAll {
		modeDisplay = "全イベントリアルタイム観察モード (-v / --watch-all) + アラート検知"
	}

	fmt.Println("================================================================================")
	fmt.Printf("  %skotowatch%s - Real-Time Process, Network & File Security Monitor (%s/%s)\n",
		colorCyan, colorReset, runtime.GOOS, runtime.GOARCH)
	fmt.Println("================================================================================")
	fmt.Printf("  管理者権限 : %s\n", adminStatus)
	fmt.Printf("  収集エンジン: %s\n", mode)
	fmt.Printf("  表示モード : %s\n", modeDisplay)
	fmt.Printf("  ルール定義 : %s (%d ルール読込済)\n", cfgPath, len(cfg.Rules))
	fmt.Printf("  監視フォルダ: %s\n", strings.Join(cfg.WatchPaths, ", "))
	fmt.Println("================================================================================")
	fmt.Println("  Ctrl+C で終了します。監視を開始しました...")
	fmt.Println()
}

func printEvent(ev model.Event) {
	ts := ev.Timestamp.Format("15:04:05.000")
	switch ev.Type {
	case model.EventProcess:
		cmd := ev.CommandLine
		if cmd == "" {
			cmd = ev.ExePath
		}
		parentInfo := ""
		if ev.ParentName != "" {
			parentInfo = fmt.Sprintf(" (Parent: %s:%d)", ev.ParentName, ev.PPID)
		}
		fmt.Printf("%s[%s] [PROC] PID:%-6d %-20s%s | Cmd: %s\n",
			colorGray, ts, ev.PID, ev.ProcessName, parentInfo, cmd+colorReset)

	case model.EventNetwork:
		domainInfo := ""
		if ev.Domain != "" {
			domainInfo = fmt.Sprintf(" (%s)", ev.Domain)
		}
		fmt.Printf("%s[%s] [NET ] PID:%-6d %-20s | %s %s:%d -> %s:%d%s%s\n",
			colorCyan, ts, ev.PID, ev.ProcessName, ev.Action,
			ev.LocalAddr, ev.LocalPort, ev.RemoteAddr, ev.RemotePort, domainInfo, colorReset)

	case model.EventDNS:
		fmt.Printf("%s[%s] [DNS ] PID:%-6d %-20s | QUERY %s -> %s%s\n",
			colorCyan, ts, ev.PID, ev.ProcessName, ev.Domain, ev.RemoteAddr, colorReset)

	case model.EventFile:
		fmt.Printf("%s[%s] [FILE] PID:%-6d %-20s | %-6s %s%s\n",
			colorYellow, ts, ev.PID, ev.ProcessName, ev.Action, ev.FilePath, colorReset)
	}
}

func printAlert(a model.Alert) {
	ev := a.Event
	ts := ev.Timestamp.Format("2006-01-02 15:04:05.000")

	sevColor := colorYellow
	if a.Severity == "HIGH" || a.Severity == "CRITICAL" {
		sevColor = colorRed
	}

	fmt.Printf("\n%s[ALERT] %s | Severity: %s | Rule: %s%s\n", sevColor, ts, a.Severity, a.RuleID, colorReset)
	fmt.Printf("  Message : %s\n", a.Description)
	if ev.PID != 0 || ev.ProcessName != "" {
		parentStr := fmt.Sprintf("PPID: %d", ev.PPID)
		if ev.ParentName != "" {
			parentStr = fmt.Sprintf("Parent: %s (%d)", ev.ParentName, ev.PPID)
		}
		fmt.Printf("  Process : %s (PID: %d / %s)\n", ev.ProcessName, ev.PID, parentStr)
	}
	if ev.User != "" {
		fmt.Printf("  User    : %s\n", ev.User)
	}
	if ev.CommandLine != "" {
		fmt.Printf("  Command : %s\n", ev.CommandLine)
	} else if ev.ExePath != "" {
		fmt.Printf("  ExePath : %s\n", ev.ExePath)
	}

	switch ev.Type {
	case model.EventNetwork:
		domainStr := ""
		if ev.Domain != "" {
			domainStr = fmt.Sprintf(" (Domain: %s)", ev.Domain)
		}
		fmt.Printf("  Network : [%s] %s:%d -> %s:%d%s\n",
			strings.ToUpper(ev.Direction), ev.LocalAddr, ev.LocalPort, ev.RemoteAddr, ev.RemotePort, domainStr)
	case model.EventDNS:
		fmt.Printf("  DNS     : %s (Resolved: %s)\n", ev.Domain, ev.RemoteAddr)
	case model.EventFile:
		fmt.Printf("  File    : [%s] %s\n", ev.Action, ev.FilePath)
	}
	fmt.Println()
}

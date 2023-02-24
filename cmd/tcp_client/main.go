//go:build !wasm
// +build !wasm

// -*- coding: utf-8 -*-
package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/emctoo/kptunnel"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const VERSION = "0.2.0"

func main() {
	// UNIX Time is faster and smaller than most timestamps
	// zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	// zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimeFieldFormat = "2006-01-02T15:04:05.999Z07:00"

	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	// short filename:lineno format, instead of full path
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		file = short
		return file + ":" + strconv.Itoa(line)
	}
	runLogFile, _ := os.OpenFile("/tmp/t.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	multi := zerolog.MultiLevelWriter(os.Stdout, runLogFile)
	log.Logger = zerolog.New(multi).With().Caller().Timestamp().Logger()

	//if kptunnel.BUFSIZE >= 65536 {
	//	fmt.Printf("BUFSIZE is illegal. -- %d", 65536)
	//}

	var cmd = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	version := cmd.Bool("version", false, "display the version")
	help := cmd.Bool("help", false, "display help message")
	cmd.Usage = func() {
		fmt.Fprintf(cmd.Output(), "\nUsage: %s <mode [-help]> [-version]\n\n", os.Args[0])
		fmt.Fprintf(cmd.Output(), " mode: \n")
		fmt.Fprintf(cmd.Output(), "    wsserver\n")
		fmt.Fprintf(cmd.Output(), "    r-wsserver\n")
		fmt.Fprintf(cmd.Output(), "    server\n")
		fmt.Fprintf(cmd.Output(), "    r-server\n")
		fmt.Fprintf(cmd.Output(), "    wsclient\n")
		fmt.Fprintf(cmd.Output(), "    r-wsclient\n")
		fmt.Fprintf(cmd.Output(), "    client\n")
		fmt.Fprintf(cmd.Output(), "    r-client\n")
		fmt.Fprintf(cmd.Output(), "    echo\n")
		fmt.Fprintf(cmd.Output(), "    heavy\n")
		os.Exit(1)
	}
	cmd.Parse(os.Args[1:])

	if *version {
		fmt.Printf("version: %s\n", VERSION)
		os.Exit(0)
	}
	if *help {
		cmd.Usage()
		os.Exit(0)
	}
	if len(cmd.Args()) > 0 {
		switch mode := cmd.Args()[0]; mode {

		case "client":
			ParseOptClient(mode, cmd.Args()[1:])
		case "r-client":
			ParseOptClient(mode, cmd.Args()[1:])
		case "wsclient":
			ParseOptClient(mode, cmd.Args()[1:])
		case "r-wsclient":
			ParseOptClient(mode, cmd.Args()[1:])
		}
		os.Exit(0)
	}
	cmd.Usage()
	os.Exit(1)
}

func ParseOpt(
	cmd *flag.FlagSet, mode string, args []string) (*kptunnel.TunnelParam, []kptunnel.Forward, func()) {

	needForward := false
	if mode == "r-server" || mode == "r-wsserver" ||
		mode == "client" || mode == "wsclient" {
		needForward = true
	}

	pass := cmd.String("pass", "", "password")
	encPass := cmd.String("encPass", "", "packet encrypt pass")
	encCount := cmd.Int("encCount", -1,
		`number to encrypt the tunnel packet.
 -1: infinity
  0: plain
  N: packet count`)
	ipPattern := cmd.String("ip", "", "allow ip range (192.168.0.1/24)")
	interval := cmd.Int("int", 20, "keep alive interval")
	ctrl := cmd.String("ctrl", "", "[bench][stop]")
	prof := cmd.String("prof", "", "profile port. (:1234)")
	console := cmd.String("console", "", "console port. (:1234)")
	verbose := cmd.Bool("verbose", false, "verbose. (true or false)")
	debug := cmd.Bool("debug", false, "debug. (true or false)")
	omitForward := cmd.Bool("omit", false, "omit forward")

	usage := func() {
		fmt.Fprintf(cmd.Output(), "\nUsage: %s %s <server> ", os.Args[0], mode)
		if needForward {
			fmt.Fprintf(cmd.Output(), "<forward [forward [...]]> ")
		} else {
			fmt.Fprintf(cmd.Output(), "[forward [forward [...]]] ")
		}
		fmt.Fprintf(cmd.Output(), "[option] \n\n")
		fmt.Fprintf(cmd.Output(), "   server: e.g. localhost:1234 or :1234\n")
		fmt.Fprintf(cmd.Output(), "   forward: <new_forward|old_forward> \n")
		fmt.Fprintf(cmd.Output(), "   new_forward: <r|t>,old_forward  e.g. r,:1234,hoge.com:5678\n")
		fmt.Fprintf(cmd.Output(), "   old_forward: listen-port,target-port  e.g. :1234,hoge.com:5678\n")
		fmt.Fprintf(cmd.Output(), "\n")
		fmt.Fprintf(cmd.Output(), " options:\n")
		cmd.PrintDefaults()
		os.Exit(1)
	}
	cmd.Usage = usage

	cmd.Parse(args)

	nonFlagArgs := []string{}
	for len(cmd.Args()) != 0 {
		workArgs := cmd.Args()

		findOp := false
		for index, arg := range workArgs {
			if strings.Index(arg, "-") == 0 {
				cmd.Parse(workArgs[index:])
				findOp = true
				break
			} else {
				nonFlagArgs = append(nonFlagArgs, arg)
			}
		}
		if !findOp {
			break
		}
	}
	if len(nonFlagArgs) < 1 {
		usage()
	}

	serverInfo := kptunnel.Hostname2HostInfo(nonFlagArgs[0])
	if serverInfo == nil {
		fmt.Print("set -server option!\n")
		usage()
	}

	var maskIP *kptunnel.MaskIP = nil
	if *ipPattern != "" {
		var err error
		maskIP, err = kptunnel.Ippattern2MaskIP(*ipPattern)
		if err != nil {
			fmt.Println(err)
			usage()
		}
	}

	kptunnel.VerboseFlag = *verbose
	kptunnel.DebugFlag = *debug

	if *pass == "" {
		fmt.Print("warning: password is default. set -pass option.\n")
	}
	if *encPass == "" {
		fmt.Print("warning: encrypt password is default. set -encPass option.\n")
	}
	magic := []byte(*pass + *encPass)

	if *interval < 2 {
		fmt.Print("'interval' is less than 2. force set 2.")
		*interval = 2
	}

	param := kptunnel.TunnelParam{Pass: pass, Mode: mode, MaskedIP: maskIP, EncPass: encPass, EncCount: *encCount, KeepAliveInterval: *interval * 1000,
		Magic: kptunnel.GetKey(magic), ServerInfo: *serverInfo, WsReqHeader: http.Header{}}
	if *ctrl != "" {
		*omitForward = true
		if *ctrl == "bench" {
			param.Ctrl = kptunnel.CTRL_BENCH
		}
		if *ctrl == "stop" {
			param.Ctrl = kptunnel.CTRL_STOP
		}
	}

	if *prof != "" {
		go func() {
			fmt.Println(http.ListenAndServe(*prof, nil))
		}()
	}

	if *console != "" {
		go func() {
			consoleHost := kptunnel.Hostname2HostInfo(*console)
			if consoleHost == nil {
				fmt.Printf("illegal host format. -- %s\n", *console)
				usage()
			}
			kptunnel.StartConsole(*consoleHost)
		}()
	}

	isReverseTunnel := false
	if mode == "r-server" || mode == "r-wsserver" ||
		mode == "r-client" || mode == "r-wsclient" {
		isReverseTunnel = true
	}

	forwardList := []kptunnel.Forward{}
	for _, arg := range nonFlagArgs[1:] {
		isReverseForward := isReverseTunnel
		tokenList := strings.Split(arg, ",")
		if len(tokenList) == 3 {
			switch tokenList[0] {
			case "r":
				isReverseForward = true
			case "t":
				isReverseForward = false
			default:
				fmt.Printf("illegal forward type '%s'. it needs to be 't' or 'r'.", tokenList[0])
				usage()
			}
			tokenList = tokenList[1:]
		}
		if len(tokenList) != 2 {
			fmt.Printf("illegal forward. need ',' -- %s", arg)
			usage()
		}
		remoteInfo := kptunnel.Hostname2HostInfo(tokenList[1])
		if remoteInfo == nil {
			fmt.Printf("illegal forward. -- %s", arg)
			usage()
		}
		srcInfo := kptunnel.Hostname2HostInfo(tokenList[0])
		if srcInfo == nil {
			fmt.Printf("illegal forward. -- %s", arg)
			usage()
		}
		forwardList = append(
			forwardList,
			kptunnel.Forward{IsReverse: isReverseForward, Src: *srcInfo, Dest: *remoteInfo})
	}
	if !*omitForward && len(forwardList) == 0 {
		if mode == "r-server" || mode == "r-wsserver" || mode == "client" || mode == "wsclient" {
			fmt.Print("set forward!")
			usage()
		}
	}

	return &param, forwardList, usage
}

func ParseOptClient(mode string, args []string) {
	var cmd = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	//userAgent := cmd.String("UA", "Go Http Client", "user agent for websocket")
	//proxyHost := cmd.String("proxy", "", "proxy server")
	//wsPath := cmd.String("wspath", "/", "websocket path")
	//session := cmd.String("session", "", "set the session ID")
	header := cmd.String("header", "", "http header. ex, 'NAME: VAL'")
	//tlsFlag := cmd.Bool("tls", false, "connect on tls")

	param, forwardList, usage := ParseOpt(cmd, mode, args)
	if *header != "" {
		token := regexp.MustCompile(":").Split(*header, 2)
		if len(token) == 2 {
			param.WsReqHeader.Add(token[0], token[1])
		} else {
			usage()
		}
	}

	//schema := "ws://"
	//if *tlsFlag {
	//	schema = "wss://"
	//}
	//wsQuery := ""
	//if *session == "" {
	//	uuidObj := uuid.New()
	//	wsQuery = "session=" + uuidObj.String()
	//} else {
	//	wsQuery = "session=" + *session
	//}

	//websocketServerInfo := kptunnel.Host{schema, param.ServerInfo.Name, param.ServerInfo.Port, *wsPath, wsQuery}

	switch mode {
	case "client":
		kptunnel.StartClient(param, forwardList)
	case "r-client":
		kptunnel.StartReverseClient(param)
		//case "wsclient":
		//	kptunnel.StartWebSocketClient(*userAgent, param, websocketServerInfo, *proxyHost, forwardList)
		//case "r-wsclient":
		//	kptunnel.StartReverseWebSocketClient(*userAgent, param, websocketServerInfo, *proxyHost)
	}
}

package kptunnel

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return StringWithCharset(length, charset)
}

// TestEchoServer waits for all clients to close
type TestEchoServer struct {
	listener net.Listener
	quitChan chan interface{}
	wg       sync.WaitGroup
}

func newTestEchoServer(addr string) *TestEchoServer {
	s := &TestEchoServer{
		quitChan: make(chan interface{}),
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal().Err(err)
	}
	s.listener = l
	s.wg.Add(1)
	go s.serve()
	return s
}

func (s *TestEchoServer) serve() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quitChan:
				return
			default:
				log.Err(err).Msgf("accept error")
			}
		} else {
			s.wg.Add(1)
			go func() {
				s.handleConnection(conn)
				s.wg.Done()
			}()
		}
	}
}

func (s *TestEchoServer) Stop() {
	close(s.quitChan)
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *TestEchoServer) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return
		}
		_, err = conn.Write([]byte(message))
		if err != nil {
			_ = conn.Close()
			return
		}
	}
}

func TestTcpEchoServer(t *testing.T) {
	s := newTestEchoServer("127.0.0.1:12023")
	defer s.Stop()

	makeEchoClientConnections(t, "localhost:12023")
}

func makeEchoClientConnections(t *testing.T, serverAddr string) {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Error("fail to connect", err)
	}
	defer func() { _ = conn.Close() }() // if it doesn't close, the server hangs

	time.Sleep(time.Second * 5) //

	tp := textproto.NewReader(bufio.NewReader(conn))
	for i := 0; i < 3; i++ {
		input := RandomString(rand.Intn(1024))
		_, err := conn.Write([]byte(input + "\n")) // \n as the delimiter
		if err != nil {
			t.Error("fail to write", err)
		}
		fmt.Printf("%d - sent: %d\n", i, len(input)+1)

		line, _ := tp.ReadLine()
		fmt.Printf("%d - recv: %d\n", i, len(line)+1)
		if strings.Compare(input, line) != 0 {
			t.Errorf("mismatch, input: %v, output: %v", input, line)
		}
	}
	println("done")
}

func defaultTunnelConfig(serverAddr string, mode string, serverInfo *Host) TunnelParam {
	pass := "42"
	encPass := "42"
	encCount := -1
	magic := GetKey([]byte(pass + encPass))
	if serverInfo == nil {
		serverInfo = Hostname2HostInfo(serverAddr)
	}
	// serverInfo := &Host{Scheme: "ws://", Name: "127.0.0.1", Port: 1034, Path: "/"}
	//serverInfo := &Host{Scheme: "", Name: "", Port: 1034, Path: "", Query: ""}
	return TunnelParam{Pass: &pass, Mode: mode, EncPass: &encPass, EncCount: encCount,
		KeepAliveInterval: 20 * 1000, Magic: magic, ServerInfo: *serverInfo, WsReqHeader: http.Header{}}
}

func startWebsocketServer(t *testing.T, serverAddr string) *http.Server {
	param := defaultTunnelConfig(serverAddr, "wsserver", nil)
	server := StartWebsocketServer(&param, []Forward{})
	go func() {
		if err := server.ListenAndServe(); err != nil {
			t.Error(err)
		}
	}()
	return server
}

func TestStartWebsocketServer(t *testing.T) {
	//echoServer := newTestEchoServer("127.0.0.1:12023")
	//defer echoServer.Stop()

	// server
	// run client: ./wsc wsclient 127.0.0.1:1034 :2022,127.0.0.1:12023 -pass 42 -encPass 42
	param := defaultTunnelConfig(":1035", "wsserver", nil)
	server := StartWebsocketServer(&param, []Forward{})
	go func() {
		//println("listening ...")
		_ = server.ListenAndServe()
	}()
	defer func() { _ = server.Shutdown(context.Background()) }()
	// time.Sleep(time.Second * 5) // TODO signal from server to notify readiness

	// clients
	// run server: ./wsd wsserver :1034 -pass 42 -encPass 42
	//if false {
	//	forwards := []Forward{
	//		{
	//			IsReverse: false,
	//			Src:             Host{Port: 2022},
	//			Dest:             Host{Name: "127.0.0.1", Port: 12023},
	//		},
	//	}
	//	serverInfo := Host{Scheme: "ws://", Name: "127.0.0.1", Port: 1034, Path: "/", Query: "session=fb018a73-2d8a-416f-bf5a-aea59aa6d4a9"}
	//	clientTunnelConfig := defaultTunnelConfig("127.0.0.1:1034", "wsclient", &serverInfo)
	//	client, _ := CreateWebsocketClient(serverInfo, &clientTunnelConfig, forwards, "", "")
	//	go client.Start()
	//}

	time.Sleep(time.Second * 5) // TODO signal from client to notify readiness

	makeEchoClientConnections(t, "127.0.0.1:2022")
}

func TestStartWebsocketClient(t *testing.T) {
	echoServer := newTestEchoServer("127.0.0.1:12023")
	defer echoServer.Stop()

	//compileCmd := exec.Command("go build -o wsd cmd/websocket_server/main.go") // compile
	//_ = compileCmd.Run()
	//_ = compileCmd.Wait()
	//fmt.Println("compilation completes")
	//
	//// wscExitChan := make(chan error)
	//wsdCmd := exec.Command("./wsd wsserver :1034 -pass 42 -encPass 42")
	//go func() {
	//	_ = wsdCmd.Start()
	//}()
	//defer func() {
	//	if err := wsdCmd.Process.Kill(); err != nil {
	//		fmt.Printf("failed to kill process %d, %v\n", wsdCmd.Process.Pid, err)
	//	}
	//}()
	//

	// clients
	// run server: ./wsd wsserver :1034 -pass 42 -encPass 42
	if true {
		forwards := []Forward{
			{
				IsReverse: false,
				Src:       Host{Port: 2022},
				Dest:      Host{Name: "127.0.0.1", Port: 12023},
			},
		}
		serverInfo := Host{Scheme: "ws://", Name: "127.0.0.1", Port: 1034, Path: "/", Query: "session=fb018a73-2d8a-416f-bf5a-aea59aa6d4a9"}
		clientTunnelConfig := defaultTunnelConfig("127.0.0.1:1034", "wsclient", &serverInfo)
		client, _ := CreateWebsocketClient(serverInfo, &clientTunnelConfig, forwards, "", "")
		go client.Start()
	}

	time.Sleep(time.Second * 10) // TODO signal from client to notify readiness
	makeEchoClientConnections(t, "127.0.0.1:2022")
}

func init() {
	// UNIX Time is faster and smaller than most timestamps
	// zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	// zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimeFieldFormat = "2006-01-02T15:04:05.999999Z07:00"

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
		return runtime.FuncForPC(pc).Name() + ":" + file + ":" + strconv.Itoa(line)
	}
	runLogFile, _ := os.OpenFile("/tmp/t.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	multi := zerolog.MultiLevelWriter(os.Stdout, runLogFile)
	log.Logger = zerolog.New(multi).With().Caller().Timestamp().Logger()
}

package kptunnel

import (
	"bufio"
	"context"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
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

func NewTestEchoServer(t *testing.T, addr string) *TestEchoServer {
	s := &TestEchoServer{
		quitChan: make(chan interface{}),
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
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
				log.Println("accept error", err)
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
	launchTcpEchoServer(t, "localhost:2345", "localhost:2345")
}

func launchTcpEchoServer(t *testing.T, listeningAddr string, connectingAddr string) {
	s := NewTestEchoServer(t, listeningAddr)
	defer s.Stop()
	makeEchoClientConnections(t, connectingAddr)
}

func makeEchoClientConnections(t *testing.T, serverAddr string) {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Error("fail to connect", err)
	}
	defer func() { _ = conn.Close() }() // if it doesn't close, the server hangs

	tp := textproto.NewReader(bufio.NewReader(conn))
	for i := 0; i < 3; i++ {
		input := RandomString(rand.Intn(1024))
		_, err := conn.Write([]byte(input + "\n")) // \n as the delimiter
		if err != nil {
			t.Error("fail to write", err)
		}

		line, _ := tp.ReadLine()
		if strings.Compare(input, line) != 0 {
			t.Errorf("mismatch, input: %v, output: %v", input, line)
		}
	}
}

func defaultTunnelConfig(serverAddr string, mode string, serverInfo *HostInfo) TunnelParam {
	pass := "42"
	encPass := "42"
	encCount := -1
	magic := GetKey([]byte(pass + encPass))
	if serverInfo == nil {
		serverInfo = Hostname2HostInfo(serverAddr)
	}
	// serverInfo := &HostInfo{Scheme: "ws://", Name: "127.0.0.1", Port: 1034, Path: "/"}
	//serverInfo := &HostInfo{Scheme: "", Name: "", Port: 1034, Path: "", Query: ""}
	return TunnelParam{Pass: &pass, Mode: mode, MaskedIP: nil, EncPass: &encPass, EncCount: encCount,
		KeepAliveInterval: 20 * 1000, Magic: magic, ServerInfo: *serverInfo, WsReqHeader: http.Header{}}
}

func startWebsocketServer(t *testing.T, serverAddr string) *http.Server {
	param := defaultTunnelConfig(serverAddr, "wsserver", nil)
	server := StartWebsocketServer(&param, []ForwardInfo{})
	go func() {
		if err := server.ListenAndServe(); err != nil {
			t.Error(err)
		}
	}()
	return server
}

func TestStartWebsocketServer1(t *testing.T) {
	param := defaultTunnelConfig(":1034", "wsserver", nil)
	server := StartWebsocketServer(&param, []ForwardInfo{})
	go func() {
		if err := server.ListenAndServe(); err != nil {
			t.Error(err)
		}
	}()
	defer server.Shutdown(context.Background())
}

func TestWebsocketServer(t *testing.T) {
	s := NewTestEchoServer(t, "localhost:2023")
	defer s.Stop()

	server := startWebsocketServer(t, ":1034")
	defer server.Shutdown(context.Background())
	//if err := server.ListenAndServe(); err != nil {
	//	t.Error(err)
	//}

	time.Sleep(time.Second * 3)

	forwards := []ForwardInfo{
		{
			IsReverseTunnel: false,
			Src:             *Hostname2HostInfo(":2022"),
			Dst:             *Hostname2HostInfo("localhost:2023"),
		},
	}
	serverInfo := HostInfo{Scheme: "ws://", Name: "127.0.0.1", Port: 1034, Path: "/", Query: "session=fb018a73-2d8a-416f-bf5a-aea59aa6d4a9"}
	clientTunnelConfig := defaultTunnelConfig("127.0.0.1:1034", "wsclient", &serverInfo)

	client, err := CreateWebsocketClient(serverInfo, &clientTunnelConfig, forwards, "", "")
	if err != nil {
		t.Fatal(err)
	}
	go client.Start()

	makeEchoClientConnections(t, "localhost:2022")
	makeEchoClientConnections(t, "localhost:2022")
	//if err := server.Shutdown(context.Background()); err != nil {
	//	t.Error(err)
	//}
}

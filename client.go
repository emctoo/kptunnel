//go:build !wasm
// +build !wasm

// -*- coding: utf-8 -*-

package kptunnel

import (
	"fmt"
	"net"
	"time"

	//"time"
	//"io"

	"github.com/rs/zerolog/log"
)

func connectTunnel(serverInfo Host, param *TunnelParam, forwardList []Forward) ([]Forward, ReconnectInfo) {
	log.Printf("start client --- %d", serverInfo.Port)
	tunnel, err := net.Dial("tcp", fmt.Sprintf("%s:%d", serverInfo.Name, serverInfo.Port))
	if err != nil {
		return nil, ReconnectInfo{nil, true, fmt.Errorf("failed to connect -- %s", err)}
	}
	log.Print("connected to server")

	connInfo := newTransport(tunnel, param.EncPass, param.EncCount, nil, false)
	overrideForwardList := forwardList
	cont := true
	overrideForwardList, cont, err = handleAuthOnClientSide(connInfo, param, forwardList)
	if err != nil {
		connInfo.Session.SetState(Session_state_authmiss)
		log.Print(err)
		tunnel.Close()
		return nil, ReconnectInfo{nil, cont, err}
	}
	return overrideForwardList, ReconnectInfo{connInfo, true, err}
}

func StartClient(param *TunnelParam, forwardList []Forward) {
	process := func() bool {
		sessionParam := *param
		forwardList, reconnectInfo := connectTunnel(param.ServerInfo, &sessionParam, forwardList)
		if reconnectInfo.Err != nil {
			return false
		}
		defer reconnectInfo.Conn.Conn.Close()

		listenGroup, localForwardList := NewListen(true, forwardList)
		defer listenGroup.Close()

		reconnect := CreateToReconnectFunc(func(sessionInfo *Session) ReconnectInfo {
			_, reconnectInfo := connectTunnel(param.ServerInfo, &sessionParam, forwardList)
			return reconnectInfo
		})
		ListenAndNewConnect(true, listenGroup, localForwardList, reconnectInfo.Conn, &sessionParam, reconnect)
		return true
	}

	for {
		if !process() {
			break
		}
	}
}

func StartReverseClient(param *TunnelParam) {
	process := func() bool {
		sessionParam := *param
		forwardList, reconnectInfo := connectTunnel(param.ServerInfo, &sessionParam, nil)
		if reconnectInfo.Err != nil {
			return false
		}
		defer reconnectInfo.Conn.Conn.Close()

		listenGroup, localForwardList := NewListen(true, forwardList)
		defer listenGroup.Close()

		reconnect := CreateToReconnectFunc(func(sessionInfo *Session) ReconnectInfo {
			_, reconnectInfo := connectTunnel(param.ServerInfo, &sessionParam, nil)
			return reconnectInfo
		})
		ListenAndNewConnect(true, listenGroup, localForwardList, reconnectInfo.Conn, &sessionParam, reconnect)
		return true
	}

	for {
		if !process() {
			break
		}
	}
}

type WebsocketClient struct {
	UserAgent     string
	TunnelConfig  *TunnelParam
	ServerInfo    Host
	ProxyHost     string
	Forwards      []Forward
	ReconnectInfo ReconnectInfo
	ListenerGroup *ListenerGroup
}

func CreateWebsocketClient(serverInfo Host, param *TunnelParam, forwardList []Forward, userAgent string, proxyHost string) (*WebsocketClient, error) {
	log.Printf("before isConnecting, forwards: %v", forwardList)
	forwardList, reconnectInfo := ConnectWebSocket(serverInfo.String(), proxyHost, userAgent, param, nil, forwardList)
	if reconnectInfo.Err != nil {
		log.Err(reconnectInfo.Err).Msgf("initial connection failed")
		return nil, reconnectInfo.Err
	}
	return &WebsocketClient{UserAgent: userAgent, TunnelConfig: param, ServerInfo: serverInfo, ProxyHost: proxyHost, Forwards: forwardList, ReconnectInfo: reconnectInfo}, nil
}

func (client *WebsocketClient) Start() {
	defer func() {
		_ = client.ReconnectInfo.Conn.Conn.Close()
	}()

	listenGroup, localForwardList := NewListen(true, client.Forwards)
	defer listenGroup.Close()

	client.ListenerGroup = listenGroup

	reconnectUrl := client.ServerInfo.String()
	if client.ServerInfo.Query != "" {
		reconnectUrl += "&"
	}
	reconnectUrl += "mode=Reconnect"

	reconnect := CreateToReconnectFunc(func(sessionInfo *Session) ReconnectInfo {
		log.Info().Msgf("reconnect to %s ...", reconnectUrl)
		_, reconnectInfo := ConnectWebSocket(reconnectUrl, client.ProxyHost, client.UserAgent, client.TunnelConfig, sessionInfo, client.Forwards)
		return reconnectInfo
	})
	ListenAndNewConnect(true, listenGroup, localForwardList, client.ReconnectInfo.Conn, client.TunnelConfig, reconnect)
}

func (client *WebsocketClient) Stop() {
	log.Printf("stop websocket client side ...")
	client.ListenerGroup.Close()
	_ = client.ReconnectInfo.Conn.Conn.Close()
	log.Printf("websocket client side exits.")
}

func StartWebSocketClient(userAgent string, param *TunnelParam, serverInfo Host, proxyHost string, inputForwards []Forward) {
	log.Printf("serverInfo: %#v", serverInfo)
	sessionParam := *param
	var reconnectInfo ReconnectInfo
	var forwardList []Forward
	for {
		forwardList, reconnectInfo = ConnectWebSocket(serverInfo.String(), proxyHost, userAgent, &sessionParam, nil, inputForwards)
		if reconnectInfo.Err == nil {
			break
		}
		time.Sleep(time.Second * 1)
	}

	defer func() {
		_ = reconnectInfo.Conn.Conn.Close()
	}()

	listenGroup, localForwardList := NewListen(true, forwardList)
	defer listenGroup.Close()

	reconnectUrl := serverInfo.String()
	if serverInfo.Query != "" {
		reconnectUrl += "&"
	}
	reconnectUrl += "mode=Reconnect"

	reconnect := CreateToReconnectFunc(func(sessionInfo *Session) ReconnectInfo {
		_, reconnectInfo := ConnectWebSocket(reconnectUrl, proxyHost, userAgent, &sessionParam, sessionInfo, forwardList)
		return reconnectInfo
	})
	ListenAndNewConnect(true, listenGroup, localForwardList, reconnectInfo.Conn, &sessionParam, reconnect)
}

func StartReverseWebSocketClient(userAgent string, param *TunnelParam, serverInfo Host, proxyHost string) {
	sessionParam := *param

	reconnectUrl := serverInfo.String()
	if serverInfo.Query != "" {
		reconnectUrl += "&"
	}
	reconnectUrl += "mode=Reconnect"

	reconnect := CreateToReconnectFunc(func(sessionInfo *Session) ReconnectInfo {
		_, reconnectInfo := ConnectWebSocket(reconnectUrl, proxyHost, userAgent, &sessionParam, sessionInfo, nil)
		return reconnectInfo
	})

	process := func() {
		forwardList, reconnectInfo := ConnectWebSocket(serverInfo.String(), proxyHost, userAgent, &sessionParam, nil, []Forward{})
		if reconnectInfo.Err != nil {
			return
		}
		defer func() {
			_ = reconnectInfo.Conn.Conn.Close()
		}()

		listenGroup, localForwardList := NewListen(true, forwardList)
		defer listenGroup.Close()

		ListenAndNewConnect(true, listenGroup, localForwardList, reconnectInfo.Conn, &sessionParam, reconnect)
	}
	for {
		process()
	}
}

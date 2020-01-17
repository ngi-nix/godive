package main

import (
	"golang.org/x/net/websocket"
)

type minediveClient struct {
	ID         uint64
	Name       string
	SecretKey  [32]byte
	PublicKey  [32]byte
	Nonce      [24]byte
	RemoteAddr string
	ws         *websocket.Conn
}

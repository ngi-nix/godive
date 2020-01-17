package main

import (
	b64 "encoding/base64"
	"errors"
	"log"
	"math/rand"
	"sync"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/net/websocket"
)

type minediveServer struct {
	clients      []*minediveClient
	clientsMutex *sync.Mutex
	nextID       uint64
	idMutex      *sync.Mutex
}

func (s *minediveServer) initMinediveServer() {
	s.clientsMutex = &sync.Mutex{}
	s.idMutex = &sync.Mutex{}
}

func (s *minediveServer) getClientByName(name string) (*minediveClient, error) {
	var c *minediveClient
	s.clientsMutex.Lock()
	for n := range s.clients {
		c = s.clients[n]
		if c.Name == name {
			s.clientsMutex.Unlock()
			return c, nil
		}
	}
	s.clientsMutex.Unlock()
	return nil, errors.New("Client not found")
}

func (s *minediveServer) dumpClients() {
	s.clientsMutex.Lock()
	if len(s.clients) == 0 {
		log.Println("dump clients: empty")
	}
	for n := range s.clients {
		log.Println("dump clients", n, s.clients[n].Name)
	}
	s.clientsMutex.Unlock()
}

func (s *minediveServer) getOtherPeer(cli *minediveClient) (*minediveClient, error) {
	s.clientsMutex.Lock()
	if len(s.clients) > 1 {
		i := rand.Intn(len(s.clients))
		c := s.clients[i]
		s.clientsMutex.Unlock()
		if c == cli {
			return cli, errors.New("getOtherPeer: same peer")
		}
		return c, nil
	}
	s.clientsMutex.Unlock()
	return cli, errors.New("getOtherPeer: no peers")
}

func (s *minediveServer) sendPeer(cli *minediveClient) {
	var c2 *minediveClient
	var m1, m2 userlistMsg
	var p1, p2 p1Users
	var err error
	c2, err = s.getOtherPeer(cli)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("other peer found", c2.Name)
	p1.Name = cli.Name
	p1.Alias, err = getAlias(cli.Name, c2)
	if err != nil {
		log.Println(err)
	}
	p2.Name = c2.Name
	p2.Alias, err = getAlias(c2.Name, cli)
	if err != nil {
		log.Println(err)
	}
	m1.Type = "userlist"
	log.Println(p2)
	m1.Users = append(m1.Users, p2)
	log.Println(m1.Users)
	log.Println(m1)
	m1.Contact = 0
	websocket.JSON.Send(cli.ws, m1)
	log.Println("sent", p2.Name, "to", cli.Name)
	m2.Type = "userlist"
	m2.Users = append(m2.Users, p1)
	m2.Contact = 1
	websocket.JSON.Send(c2.ws, m2)
	log.Println("sent", p1.Name, "to", c2.Name)
}

func (s *minediveServer) decryptAlias(alias string, gwName string) (string, error) {
	var encrypted, decrypted []byte
	var decryptNonce [24]byte
	gw, err := s.getClientByName(gwName)
	if err != nil {
		log.Println(err)
		return "", err
	}
	encrypted, err = b64.StdEncoding.DecodeString(alias)
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &gw.SecretKey)
	if ok != true {
		return "", errors.New("decryption failed")
	}
	a, err := s.getClientByName(string(decrypted))
	if err != nil {
		log.Println(err)
		return "nil", err
	}
	return b64.StdEncoding.EncodeToString(a.PublicKey[:]), nil
}

func (s *minediveServer) fwdToTarget(m *webrtcMsg) {
	s.clientsMutex.Lock()
	var c *minediveClient
	for n := range s.clients {
		c = s.clients[n]
		if c.Name == m.Target {
			websocket.JSON.Send(c.ws, m)
		}
	}
	s.clientsMutex.Unlock()
}

func (s *minediveServer) sendKey(cli *minediveClient, req *keyReq) {
	var msg keyMsg
	if cli.Name == req.GW {
		log.Println("Client is his own GW")
		return
	}
	aliasKey, err := s.decryptAlias(req.Alias, req.GW)
	if err != nil {
		log.Println(err)
		return
	}
	msg.Type = "key"
	msg.Alias = req.Alias
	msg.Key = aliasKey
	log.Println("Sending Message: ", msg)
	websocket.JSON.Send(cli.ws, msg)
}

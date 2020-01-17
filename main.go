package main

import (
	crand "crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	rand "math/rand"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
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

type p2Users struct {
	Name  string `json:"name"`
	Alias string `json:"alias"`
}

type userlistMsg struct {
	Type    string    `json:"type"`
	Contact int       `json:"contact"`
	Users   []p2Users `json:"users"`
}

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

var s minediveServer

func dumpClients() {
	s.clientsMutex.Lock()
	if len(s.clients) == 0 {
		log.Println("dump clients: empty")
	}
	for n := range s.clients {
		log.Println("dump clients", n, s.clients[n].Name)
	}
	s.clientsMutex.Unlock()
}

func getOtherPeer(cli *minediveClient) (*minediveClient, error) {
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

func incNonce(a []byte, dyn int) error {
	l := len(a)
	for i := 1; i <= dyn; i++ {
		if a[l-i] < 0xff {
			a[l-i]++
			return nil
		}
		a[l-i] = 0
	}
	return errors.New("incNonce: nonce expired")
}

func getAlias(username string, gw *minediveClient) (string, error) {
	var alias string
	var err error
	enc := secretbox.Seal(gw.Nonce[:], []byte(username), &gw.Nonce, &gw.SecretKey)
	alias = b64.StdEncoding.EncodeToString(enc)
	return alias, err
}

func sendPeer(cli *minediveClient) {
	var c2 *minediveClient
	var m1, m2 userlistMsg
	var p1, p2 p2Users
	var err error
	c2, err = getOtherPeer(cli)
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

type idMsg struct {
	Type string `json:"type"`
	ID   uint64 `json:"id"`
}

type usernameMsg struct {
	Type string `json:"type"`
	ID   uint64 `json:"id"`
	Name string `json:"name"`
	PK   string `json:"pk"`
}

type webrtcMsg struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Target string `json:"target"`
	SDP    string `json:"sdp"`
}

type keyReq struct {
	Type  string `json:"type"`
	Alias string `json:"alias"`
	GW    string `json:"gw"`
}

type keyMsg struct {
	Type  string `json:"type"`
	Alias string `json:"alias"`
	Key   string `json:"key"`
}

func fwdToTarget(m *webrtcMsg) {
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

func decryptAlias(alias string, gwName string) (string, error) {
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
	//return "nil", errors.New("Decryption failed")
}

func sendKey(cli *minediveClient, req *keyReq) {
	var msg keyMsg
	if cli.Name == req.GW {
		log.Println("Client is his own GW")
		return
	}
	aliasKey, err := decryptAlias(req.Alias, req.GW)
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

func echoServer(ws *websocket.Conn) {
	log.Println(ws.Config())
	var cli minediveClient
	s.idMutex.Lock()
	cli.ID = s.nextID
	s.nextID++
	s.idMutex.Unlock()
	cli.ws = ws
	cli.RemoteAddr = ws.RemoteAddr().String()
	if _, err := io.ReadFull(crand.Reader, cli.SecretKey[:]); err != nil {
		panic(err)
	}
	var msg = idMsg{Type: "id", ID: cli.ID}
	websocket.JSON.Send(ws, msg)
	//log.Println("new ws client created with id: ", cli.ID, "from", cli.RemoteAddr)
	s.clientsMutex.Lock()
	s.clients = append(s.clients, &cli)
	s.clientsMutex.Unlock()
	for {
		var jmsg []byte
		var imsg idMsg
		websocket.Message.Receive(ws, &jmsg)
		if jmsg != nil {
			var err error
			err = json.Unmarshal(jmsg, &imsg)
			if err != nil {
				log.Println(err.Error())
			} else {
				log.Println("New msg:", imsg.Type)
				switch imsg.Type {
				case "username":
					var umsg usernameMsg
					err = json.Unmarshal(jmsg, &umsg)
					if err != nil {
						log.Panic(err.Error())
					}
					log.Println(umsg)
					cli.Name = umsg.Name
					b64pk, _ := b64.StdEncoding.DecodeString(umsg.PK)
					copy(cli.PublicKey[:], b64pk[:32])
				case "message":
					log.Println("message not used")
				case "getkey":
					var kreq keyReq
					err = json.Unmarshal(jmsg, &kreq)
					sendKey(&cli, &kreq)
				case "getalias":
					log.Println("getalias not used")
				case "getpeers":
					sendPeer(&cli)
				case "offer":
					var rtcmsg webrtcMsg
					err = json.Unmarshal(jmsg, &rtcmsg)
					fwdToTarget(&rtcmsg)
				case "answer":
					var rtcmsg webrtcMsg
					err = json.Unmarshal(jmsg, &rtcmsg)
					fwdToTarget(&rtcmsg)
				default:
					log.Println(imsg.Type)
				}
			}
		} else {
			time.Sleep(300 * time.Millisecond)
		}
	}
}

func checkOrigin(config *websocket.Config, req *http.Request) (err error) {
	config.Origin, err = websocket.Origin(config, req)
	if err == nil {
		//log.Println(config.Origin)
	} else {
		//log.Println("CHECKORIGINERROR", err.Error())
		return err
	}
	return
}

func main() {
	s.initMinediveServer()
	//w := websocket.Server{
	//	Handshake: checkOrigin,
	//	Handler:   websocket.Handler(echoServer),
	//}
	hs := &http.Server{
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadHeaderTimeout: 20 * time.Second,
		Addr:              ":6501",
		Handler:           websocket.Handler(echoServer),
	}
	//hs.Handle("/", w)

	//	err := http.ListenAndServeTLS(
	//		"www.pubbo.it:6501",
	//		"/etc/letsencrypt/live/www.pubbo.it/fullchain.pem",
	//		"/etc/letsencrypt/live/www.pubbo.it/privkey.pem",
	//		nil,
	//	)
	err := hs.ListenAndServe()
	if err != nil {
		panic("ListenAndServeTLS: " + err.Error())
	}
}

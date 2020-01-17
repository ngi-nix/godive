package main

type p1Users struct {
	Name  string `json:"name"`
	Alias string `json:"alias"`
}

type userlistMsg struct {
	Type    string    `json:"type"`
	Contact int       `json:"contact"`
	Users   []p1Users `json:"users"`
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

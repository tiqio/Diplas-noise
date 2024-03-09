package model

import (
	"strconv"
	"time"
)

// Server model
type Server struct {
	KeyPair   *ServerKeypair
	Interface *ServerInterface
}

// ServerKeypair model
type ServerKeypair struct {
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	UpdateAt   time.Time `json:"updated_at"`
}

// ServerInterface model
type ServerInterface struct {
	Address    string    `json:"address"`
	ListenPort int       `json:"listen_port,string"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (server *Server) String() string {
	return server.Interface.Address + ":" + strconv.Itoa(server.Interface.ListenPort)
}

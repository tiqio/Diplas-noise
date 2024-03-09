package model

import "time"

// ClientKeypair model
type ClientKeypair struct {
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	UpdateAt   time.Time `json:"updated_at"`
}

func (clientKeyPair *ClientKeypair) String() string {
	return clientKeyPair.PrivateKey
}

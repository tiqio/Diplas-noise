package model

import (
	"strconv"
	"time"
)

// Endpoint model
type Endpoint struct {
	Address  string    `json:"address"`
	Port     int       `json:"port,string"`
	UpdateAt time.Time `json:"updated_at"`
}

func (end *Endpoint) String() string {
	return end.Address + ":" + strconv.Itoa(end.Port)
}

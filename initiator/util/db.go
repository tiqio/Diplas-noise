package util

import (
	"Diplas/initiator/model"
	noise2 "Diplas/initiator/noise"
	"github.com/sdomino/scribble"
	"os"
	"path"
	"time"
)

const dbPath = "./initiator/db"
const defaultServerAddress = "0.0.0.0"
const defaultServerPort = 51820

func DBConn() (*scribble.Driver, error) {
	db, err := scribble.New(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func InitDB() error {
	var clientPath string = path.Join(dbPath, "client")
	var clientInterfacePath string = path.Join(dbPath, "interfaces.json")
	var clientKeyPairPath string = path.Join(dbPath, "keypair.json")

	// create directories if they do not exit
	if _, err := os.Stat(clientPath); os.IsNotExist(err) {
		os.MkdirAll(clientPath, os.ModePerm)
	}

	// server's endpoint
	if _, err := os.Stat(clientInterfacePath); os.IsNotExist(err) {
		db, err := DBConn()
		if err != nil {
			return err
		}

		clientEndpoint := new(model.Endpoint)
		clientEndpoint.Address = defaultServerAddress
		clientEndpoint.Port = defaultServerPort
		clientEndpoint.UpdateAt = time.Now().UTC()
		db.Write("client", "endpoint", clientEndpoint)
	}

	// server's key pair
	if _, err := os.Stat(clientKeyPairPath); os.IsNotExist(err) {
		db, err := DBConn()
		if err != nil {
			return err
		}

		sk, pk, err := noise2.NewKeyPair()
		if err != nil {
			return scribble.ErrMissingCollection
		}
		clientKeyPair := new(model.ClientKeypair)
		clientKeyPair.PrivateKey = sk.String()
		clientKeyPair.PublicKey = pk.String()
		clientKeyPair.UpdateAt = time.Now().UTC()
		db.Write("client", "keypair", clientKeyPair)
	}

	return nil
}

func GetEndpoint() (model.Endpoint, error) {
	end := model.Endpoint{}

	db, err := DBConn()
	if err != nil {
		return end, err
	}
	if err := db.Read("client", "endpoint", &end); err != nil {
		return end, err
	}

	return end, nil
}

func GetClientKeyPair() (model.ClientKeypair, error) {
	clientKeyPair := model.ClientKeypair{}

	db, err := DBConn()
	if err != nil {
		return clientKeyPair, err
	}

	if err := db.Read("client", "keypair", &clientKeyPair); err != nil {
		return clientKeyPair, err
	}

	return clientKeyPair, nil
}

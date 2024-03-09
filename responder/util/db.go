package util

import (
	"Diplas/responder/model"
	noise2 "Diplas/responder/noise"
	"github.com/sdomino/scribble"
	"os"
	"path"
	"time"
)

const dbPath = "./responder/db"
const defaultUsername = "admin"
const defaultPassword = "admin"
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
	var serverPath string = path.Join(dbPath, "server")
	var serverInterfacePath string = path.Join(dbPath, "interfaces.json")
	var serverKeyPairPath string = path.Join(dbPath, "keypair.json")
	var userPath string = path.Join(dbPath, "users.json")

	// create directories if they do not exit
	if _, err := os.Stat(serverPath); os.IsNotExist(err) {
		os.MkdirAll(serverPath, os.ModePerm)
	}

	// server's interface
	if _, err := os.Stat(serverInterfacePath); os.IsNotExist(err) {
		db, err := DBConn()
		if err != nil {
			return err
		}

		serverInterface := new(model.ServerInterface)
		serverInterface.Address = defaultServerAddress
		serverInterface.ListenPort = defaultServerPort
		serverInterface.UpdatedAt = time.Now().UTC()
		db.Write("server", "interfaces", serverInterface)
	}

	// server's key pair
	if _, err := os.Stat(serverKeyPairPath); os.IsNotExist(err) {
		db, err := DBConn()
		if err != nil {
			return err
		}

		sk, pk, err := noise2.NewKeyPair()
		if err != nil {
			return scribble.ErrMissingCollection
		}
		serverKeyPair := new(model.ServerKeypair)
		serverKeyPair.PrivateKey = sk.String()
		serverKeyPair.PublicKey = pk.String()
		serverKeyPair.UpdateAt = time.Now().UTC()
		db.Write("server", "keypair", serverKeyPair)
	}

	// user info
	if _, err := os.Stat(userPath); os.IsNotExist(err) {
		db, err := DBConn()
		if err != nil {
			return err
		}

		user := new(model.User)
		user.Username = defaultUsername
		user.Password = defaultPassword
		db.Write("server", "users", user)
	}

	return nil
}

func GetUser() (model.User, error) {
	user := model.User{}

	db, err := DBConn()
	if err != nil {
		return user, err
	}
	if err := db.Read("server", "users", &user); err != nil {
		return user, err
	}

	return user, nil
}

func GetServer() (model.Server, error) {
	server := model.Server{}

	db, err := DBConn()
	if err != nil {
		return server, err
	}

	serverInterface := model.ServerInterface{}
	if err := db.Read("server", "interfaces", &serverInterface); err != nil {
		return server, err
	}

	serverKeyPair := model.ServerKeypair{}
	if err := db.Read("server", "keypair", &serverKeyPair); err != nil {
		return server, err
	}
	server.Interface = &serverInterface
	server.KeyPair = &serverKeyPair
	return server, nil
}

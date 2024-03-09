package main

import (
	noise2 "Diplas/initiator/noise"
	"Diplas/initiator/util"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/songgao/water"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var (
	Ei_priv noise2.NoisePrivateKey
	Ei_pub  noise2.NoisePublicKey
)

const (
	MaxMessageSize = 65535
)

const (
	MessageInitiationSize = 116
	MessageResponseSize   = 60
)

func init() {
	Ei_priv, Ei_pub, _ = noise2.NewKeyPair()
}

var conn *net.UDPConn
var Ti_send noise2.NoiseSymmetricKey
var Ti_recv noise2.NoiseSymmetricKey

func main() {
	err := util.InitDB()
	if err != nil {
		fmt.Println("数据库初始化失败:", err)
	}

	end, _ := util.GetEndpoint()
	keypair, _ := util.GetClientKeyPair()
	fmt.Println("end:", end.String())
	fmt.Println("keypair:", keypair.String())

	println("initiator")

	// http
	serverURL := fmt.Sprintf("http://%s:%d", end.Address, end.Port)

	response, err := http.Get(serverURL)
	if err != nil {
		fmt.Println("HTTP请求失败:", err)
		return
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("读取响应体失败:", err)
		return
	}

	fmt.Println("响应状态码:", response.Status)
	//fmt.Println("响应体:", string(responseBody))

	// udp

	var Er_pub noise2.NoisePublicKey
	copy(Er_pub[:], responseBody)
	//fmt.Println("Er_pub:", Er_pub)
	var Si_priv noise2.NoisePrivateKey
	copy(Si_priv[:], keypair.PrivateKey)

	// create msg1

	//fmt.Println("==> Er_pub:", Er_pub)
	msg1, create_vars, _ := noise2.CreateMessageInitiation(Ei_priv, Si_priv, Er_pub)
	fmt.Println("msg1:", msg1)
	fmt.Println("create_vars.h4:", create_vars.H4)

	var buf [MessageInitiationSize]byte
	writer := bytes.NewBuffer(buf[:0])
	err = binary.Write(writer, binary.LittleEndian, msg1)
	if err != nil {
		fmt.Println("msg1序列化失败:", err)
	}
	packet := writer.Bytes()
	//fmt.Println("msg1序列化后得到packet:", packet)

	serverAddr := fmt.Sprintf("%s:%d", end.Address, end.Port+1)
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		fmt.Println("udp解析地址失败:", err)
	}
	conn, err = net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println("udp连接创建失败:", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		fmt.Println("发送数据失败:", err)
	}

	fmt.Println("msg1数据成功发送到服务端。")

	// msg2接收

	buffer := make([]byte, MaxMessageSize)
	n, peerAddr, err := conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("udp接收数据失败:", err)
		return
	}
	fmt.Printf("从服务端 %s 收到消息:\n", peerAddr)
	for i := 0; i < n; i++ {
		fmt.Printf("%d ", buffer[i])
	}
	fmt.Println()

	// consume msg2

	packet2 := buffer[:n]
	var msg2 noise2.MessageResponse
	reader := bytes.NewReader(packet2)
	err = binary.Read(reader, binary.LittleEndian, &msg2)
	if err != nil {
		fmt.Println("msg2反序列化失败:", err)
	}
	//fmt.Println("反序列化后的msg2:", msg2)
	//fmt.Println("msg2.Static", len(msg1.Static), msg2.Static)

	Ti_send, Ti_recv, _ = noise2.ConsumeMessageResponse(&msg2, Ei_priv, create_vars)
	fmt.Println("Ti_send:", Ti_send)
	fmt.Println("Ti_recv:", Ti_recv)

	// createTun
	iface, err := createTun("10.10.10.1")
	if err != nil {
		fmt.Println("interface can not created:", err)
		return
	}
	//conn, err = createConn()
	go listen(iface)
	go listenInterface(iface)

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, syscall.SIGTERM)
	<-termSignal
	fmt.Println("closing")
}

func createTun(ip string) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, err
	}
	log.Printf("Interface Name: %s\n", iface.Name())
	out, err := util.RunCommand(fmt.Sprintf("sudo ip addr add %s/24 dev %s", ip, iface.Name()))
	if err != nil {
		fmt.Println(out)
		return nil, err
	}

	out, err = util.RunCommand(fmt.Sprintf("sudo ip link set dev %s up", iface.Name()))
	if err != nil {
		fmt.Println(out)
		return nil, err
	}
	return iface, nil
}

func listen(iface *water.Interface) {
	for {
		fmt.Println("udp connection listening")
		message := make([]byte, 65535)
		for {
			n, err := conn.Read(message)
			if err != nil {
				log.Println("conn read error:", err)
			}

			// decrypt
			decryptCode := util.AesDecrypt(message[:n], Ti_recv[:])

			if iface != nil {
				_, err = iface.Write(decryptCode)
				if err != nil {
					log.Println("ifce write err:", err)
				} else {
					fmt.Println("iface write done")
				}
			}
			fmt.Println("START - incoming packet from TUNNEL")
			util.WritePacket(message[:n])
			fmt.Println("DONE - incoming packet from TUNNEL")
		}
	}
}

func listenInterface(iface *water.Interface) {
	fmt.Println("interface listening")
	packet := make([]byte, 65535)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			log.Println("ifce read error:", err)
		}

		// encrypt
		encryptCode := util.AesEncrypt(packet[:n], Ti_send[:])

		if err == nil {
			_, err = conn.Write(encryptCode)
			if err != nil {
				log.Println("conn write error:", err)
			}
		}
		fmt.Println("START - incoming packet from INTERFACE")
		util.WritePacket(packet[:n])
		fmt.Println("DONE - incoming packet from INTERFACE")
	}
}

package main

import (
	noise2 "Diplas/responder/noise"
	"Diplas/responder/util"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/songgao/water"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var (
	Er_priv noise2.NoisePrivateKey
	Er_pub  noise2.NoisePublicKey
)

const (
	MaxMessageSize = 65535
)

const (
	MessageInitiationSize = 116
	MessageResponseSize   = 60
)

func init() {
	Er_priv, Er_pub, _ = noise2.NewKeyPair()
	fmt.Println("==> init_Er_priv:", Er_priv)
	fmt.Println("==> init_Er_pub:", Er_pub)
}

func handler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write(Er_pub[:])
	if err != nil {
		http.Error(w, "Er_pub放入ResponseWriter失败。", http.StatusInternalServerError)
	}
}

var conn *net.UDPConn
var peerAddr *net.UDPAddr
var Tr_send noise2.NoiseSymmetricKey
var Tr_recv noise2.NoiseSymmetricKey

func main() {
	err := util.InitDB()
	if err != nil {
		fmt.Println("数据库初始化失败:", err)
	}

	user, _ := util.GetUser()
	server, _ := util.GetServer()
	fmt.Println(user.String())
	fmt.Println(server.String())

	println("responder")

	// http
	http.HandleFunc("/", handler)
	port := server.Interface.ListenPort
	serverAddr := fmt.Sprintf("%s:%d", server.Interface.Address, port)
	fmt.Printf("http服务端启动，监听端口 %d。\n", port)
	go http.ListenAndServe(serverAddr, nil)

	// udp
	serverAddr = fmt.Sprintf("%s:%d", server.Interface.Address, port+1)
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		fmt.Println("解析地址失败:", err)
		return
	}
	conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("创建UDP连接失败:", err)
		return
	}
	defer conn.Close()

	fmt.Printf("udp服务端启动，监听端口 %d。\n", port+1)
	fmt.Println("等待客户端连接...")

	buffer := make([]byte, MaxMessageSize)
	var n int
	n, peerAddr, err = conn.ReadFromUDP(buffer)
	if err != nil {
		fmt.Println("udp接收数据失败:", err)
		return
	}

	fmt.Printf("从客户端 %s 收到消息:\n", peerAddr)
	for i := 0; i < n; i++ {
		fmt.Printf("%d ", buffer[i])
	}
	fmt.Println()

	packet := buffer[:n]
	var msg1 noise2.MessageInitiation
	reader := bytes.NewReader(packet)
	err = binary.Read(reader, binary.LittleEndian, &msg1)
	if err != nil {
		fmt.Println("msg1反序列化失败:", err)
	}
	//fmt.Println("反序列化后的msg1:", msg1)
	//fmt.Println("msg1.Ephemeral", len(msg1.Ephemeral), msg1.Ephemeral)
	Ei_pub := msg1.Ephemeral
	//fmt.Println("msg1.Static", len(msg1.Static), msg1.Static)
	//fmt.Println("msg1.Timestamp", len(msg1.Timestamp), msg1.Timestamp)

	// consume msg1

	consume_vars, _ := noise2.ConsumeMessageInitiation(&msg1, Er_priv, Ei_pub)
	fmt.Println("consume_vars.H4", consume_vars.H4)

	// create msg2
	var Sr_priv noise2.NoisePrivateKey
	hex_Sr_priv, _ := hex.DecodeString(server.KeyPair.PrivateKey)
	copy(Sr_priv[:], hex_Sr_priv)
	var msg2 *noise2.MessageResponse
	msg2, Tr_recv, Tr_send, _ = noise2.CreateMessageResponse(Sr_priv, Ei_pub, consume_vars)
	fmt.Println("Tr_recv:", Tr_recv)
	fmt.Println("Tr_send:", Tr_send)

	// msg2序列化
	var buf [MessageResponseSize]byte
	writer := bytes.NewBuffer(buf[:0])
	err = binary.Write(writer, binary.LittleEndian, msg2)
	if err != nil {
		fmt.Println("msg2序列化失败:", err)
	}
	packet2 := writer.Bytes()

	// udp发送
	_, err = conn.WriteToUDP(packet2, peerAddr)
	if err != nil {
		fmt.Println("发送数据失败:", err)
	}

	fmt.Println("packet2发送成功。")

	iface, err := createTun("10.10.10.2")
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
			decryptCode := util.AesDecrypt(message[:n], Tr_recv[:])

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
		encryptCode := util.AesEncrypt(packet[:n], Tr_send[:])

		if conn != nil {
			_, err = conn.WriteToUDP(encryptCode, peerAddr)
			if err != nil {
				log.Println("conn write error:", err)
			}
		}

		fmt.Println("START - incoming packet from INTERFACE")
		util.WritePacket(packet[:n])
		fmt.Println("DONE - incoming packet from INTERFACE")
	}
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

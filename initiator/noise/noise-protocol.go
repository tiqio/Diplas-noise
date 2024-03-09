package noise

import (
	"Diplas/initiator/tai64n"
	"fmt"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

const (
	NoiseConstruction = "Noise_XX_25519_ChaChaPoly_BLAKE2s"
	DiplasIdentifier  = "Diplas v1 215572162@qq.com"
)

const (
	MessageInitiationType = 1
	MessageResponseType   = 2
	MessageTransportType  = 3
)

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
}

type MessageResponse struct {
	Type     uint32
	Sender   uint32
	Receiver uint32
	Static   [NoisePublicKeySize + poly1305.TagSize]byte
}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(DiplasIdentifier))
}

func CreateMessageInitiation(Ei_priv NoisePrivateKey, Si_priv NoisePrivateKey, Er_pub NoisePublicKey) (*MessageInitiation, Variables, error) {
	// prepare variables
	hash := InitialHash // h1
	//fmt.Println("==> hash1:", hash)
	ck := InitialChainKey // ck0
	var vars Variables

	mixHash(&hash, &hash, Er_pub[:]) // h2 = Hash(h1 || Er_pub)

	// create msg
	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: Ei_priv.publicKey(),
	}
	//fmt.Println("==> hash2:", hash)

	mixHash(&hash, &hash, msg.Ephemeral[:]) // h3 = Hash(h2 || Ei_pub)
	mixKey(&ck, &ck, msg.Ephemeral[:])      // ck1 = HKDF1(ck0, Ei_pub)

	// encrypt static key
	ee := Ei_priv.sharedSecret(Er_pub)
	var key [chacha20poly1305.KeySize]byte
	KDF2(&ck, &key, ck[:], ee[:]) // (ck2, k0) = HKDF2(ck1, DH(Ei_priv, Er_pub))
	aead, _ := chacha20poly1305.New(key[:])
	var Si_pub = Si_priv.publicKey()
	aead.Seal(msg.Static[:0], ZeroNonce[:], Si_pub[:], hash[:]) // enc-id = aead-enc(k0, 0, Si_pub, h3)
	//fmt.Println("==> hash3:", hash[:])
	mixHash(&hash, &hash, msg.Static[:]) // H4 = Hash(h3 || enc-id)

	// encrypt timestamp
	se := Si_priv.sharedSecret(Er_pub)
	KDF2(&ck, &key, ck[:], se[:])
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], hash[:]) // enc-time = aead-enc(K1, 0, time, H4)

	// assign index
	msg.Sender = 1

	vars.H4 = hash
	vars.CK3 = ck
	vars.K1 = key

	return &msg, vars, nil
}

func ConsumeMessageInitiation(msg *MessageInitiation, Er_priv NoisePrivateKey, Ei_pub NoisePublicKey) (Variables, error) {
	// prepare variables
	hash := InitialHash   // h1
	ck := InitialChainKey // ck0
	var vars Variables

	if msg.Type != MessageInitiationType {
		return vars, nil
	}

	Er_pub := Er_priv.publicKey()
	mixHash(&hash, &InitialHash, Er_pub[:]) // h2 = Hash(h1 || Er_pub)
	mixHash(&hash, &hash, msg.Ephemeral[:]) // h3 = Hash(h2 || Ei_pub)
	mixKey(&ck, &ck, msg.Ephemeral[:])      // ck1 = HKDF1(ck0, Ei_pub)

	// decrypt static key
	ss := Er_priv.sharedSecret(Ei_pub)
	var key [chacha20poly1305.KeySize]byte
	KDF2(&ck, &key, ck[:], ss[:]) // (ck2, k0) = HKDF2(ck1, DH(Er_priv, Er_pub))
	aead, _ := chacha20poly1305.New(key[:])

	var Si_pub NoisePublicKey
	_, err := aead.Open(Si_pub[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return vars, nil
	}
	mixHash(&hash, &hash, msg.Static[:]) // H4 = Hash(h3 || enc-id)

	// decrypt timestamp
	var timestamp tai64n.Timestamp
	se := Er_priv.sharedSecret(Si_pub)
	KDF2(&ck, &key, ck[:], se[:]) // (CK3, K1) = HKDF2(ck2, DH(Sr_priv, Ei_pub))
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:]) // aead-dec(K1, 0, enc-time, H4)
	if err != nil {
		return vars, nil
	}

	vars.H4 = hash
	vars.CK3 = ck
	vars.K1 = key

	return vars, nil
}

func CreateMessageResponse(Sr_priv NoisePrivateKey, Ei_pub NoisePublicKey, vars Variables) (*MessageResponse, NoiseSymmetricKey, NoiseSymmetricKey, error) {
	// prepare variables
	hash := vars.H4 // H4
	ck := vars.CK3  // CK3
	key := vars.K1  // K1

	// create msg
	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = 2
	msg.Receiver = 1

	// encrypt static key
	aead, _ := chacha20poly1305.New(key[:])
	var Sr_pub = Sr_priv.publicKey()
	aead.Seal(msg.Static[:0], ZeroNonce[:], Sr_pub[:], hash[:]) // enc-id = aead-enc(k0, 0, Si_pub, h3)

	// derive receive/send key
	es := Sr_priv.sharedSecret(Ei_pub)
	fmt.Println("CreateMessageInitiation-es:", es)
	var key_recv, key_send [chacha20poly1305.KeySize]byte
	KDF2(&key_recv, &key_send, ck[:], es[:])
	Tr_recv := NoiseSymmetricKey(key_recv)
	Tr_send := NoiseSymmetricKey(key_send)

	return &msg, Tr_recv, Tr_send, nil
}

func ConsumeMessageResponse(msg *MessageResponse, Ei_priv NoisePrivateKey, vars Variables) (NoiseSymmetricKey, NoiseSymmetricKey, error) {
	// prepare variables
	hash := vars.H4 // H4
	ck := vars.CK3  // CK3
	key := vars.K1  // K1

	if msg.Type != MessageResponseType {
		return hash, hash, nil
	}

	// decrypt static key
	var Sr_pub NoisePublicKey
	aead, _ := chacha20poly1305.New(key[:])
	_, err := aead.Open(Sr_pub[:0], ZeroNonce[:], msg.Static[:], hash[:]) // aead-dec(K1, 0, enc-id, H4)
	if err != nil {
		return hash, hash, nil
	}

	// derive send/receive key
	es := Ei_priv.sharedSecret(Sr_pub)
	fmt.Println("ConsumeMessageResponse-es:", es)
	var key_send, key_recv [chacha20poly1305.KeySize]byte
	KDF2(&key_send, &key_recv, ck[:], es[:])
	Ti_send := NoiseSymmetricKey(key_send)
	Ti_recv := NoiseSymmetricKey(key_recv)

	return Ti_send, Ti_recv, nil
}

package noise

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"hash"
)

const (
	NoisePublicKeySize  = 32
	NoisePrivateKeySize = 32
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoiseSymmetricKey [chacha20poly1305.KeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
)

type Variables struct {
	H4  [blake2s.Size]byte
	CK3 [blake2s.Size]byte
	K1  [blake2s.Size]byte
}

func newPrivateKey() (sk NoisePrivateKey, err error) {
	_, err = rand.Read(sk[:])
	return
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

func NewKeyPair() (NoisePrivateKey, NoisePublicKey, error) {
	sk, err := newPrivateKey()
	pk := sk.publicKey()
	return sk, pk, err
}

func (sk *NoisePrivateKey) String() string {
	return hex.EncodeToString(sk[:])
}

func (pk *NoisePublicKey) String() string {
	return hex.EncodeToString(pk[:])
}

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarMult(&ss, ask, apk)
	return ss
}

func mixHash(dst *[blake2s.Size]byte, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func mixKey(dst *[blake2s.Size]byte, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func HMAC1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

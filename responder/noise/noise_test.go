package noise

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCurveWrappers(t *testing.T) {
	sk1, _ := newPrivateKey()
	sk2, _ := newPrivateKey()

	pk1 := sk1.publicKey()
	pk2 := sk2.publicKey()

	fmt.Println("sk1:", sk1, "\npk1:", pk1)
	fmt.Println("sk2:", sk2, "\npk2:", pk2)

	ss1 := sk1.sharedSecret(pk2)
	ss2 := sk2.sharedSecret(pk1)

	fmt.Println("ss1:", ss1)
	fmt.Println("ss2:", ss2)

	if ss1 != ss2 {
		t.Fatal("Failed to compute shared secret")
	}
}

func TestNoiseHandshake(t *testing.T) {
	// Er_priv
	var Er_priv NoisePrivateKey
	var Er_pub NoisePublicKey
	hex_Er_priv, _ := hex.DecodeString("f70dbb6b1b92a1dde1c783b297016af3f572fef13b0abb16a2623d89a58e9725")
	copy(Er_priv[:], hex_Er_priv)
	Er_pub = Er_priv.publicKey()

	// Ei_priv
	var Ei_priv NoisePrivateKey
	var Ei_pub NoisePublicKey
	hex_Ei_priv, _ := hex.DecodeString("49e80929259cebdda4f322d6d2b1a6fad819d603acd26fd5d845e7a123036427")
	copy(Ei_priv[:], hex_Ei_priv)
	Ei_pub = Ei_priv.publicKey()

	// Sr_priv; send enc-id
	var Sr_priv NoisePrivateKey
	//var Sr_pub NoisePublicKey
	hex_Sr_priv, _ := hex.DecodeString("481eb0d8113a4a5da532d2c3e9c14b53c8454b34ab109676f6b58c2245e37b58")
	copy(Sr_priv[:], hex_Sr_priv)
	//Sr_pub = Sr_priv.publicKey()

	// Si_priv; send enc-id
	var Si_priv NoisePrivateKey
	//var Si_pub NoisePublicKey
	hex_Si_priv, _ := hex.DecodeString("481eb0d8113a4a5da532d2c3e9c14b53c8454b34ab109676f6b58c2245e37b58")
	copy(Si_priv[:], hex_Si_priv)
	//Si_pub = Si_priv.publicKey()

	// create msg1
	msg1, create_vars, _ := CreateMessageInitiation(Ei_priv, Si_priv, Er_pub)
	// consume msg1
	consume_vars, _ := ConsumeMessageInitiation(msg1, Er_priv, Ei_pub)
	fmt.Println("create_vars.H4:", create_vars.H4)
	fmt.Println("consume_vars.H4:", consume_vars.H4)

	// create msg2
	msg2, Tr_recv, Tr_send, _ := CreateMessageResponse(Sr_priv, Ei_pub, consume_vars)
	// consume msg2
	Ti_send, Ti_recv, _ := ConsumeMessageResponse(msg2, Ei_priv, create_vars)
	fmt.Println("Tr_recv:", Tr_recv)
	fmt.Println("Ti_send:", Ti_send)
	fmt.Println("Tr_send:", Tr_send)
	fmt.Println("Ti_recv:", Ti_recv)
}

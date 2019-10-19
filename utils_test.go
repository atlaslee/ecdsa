package ecdsa

import (
	"crypto/rand"
	"testing"
)

func TestPublicKeyFromPrivateKey(t *testing.T) {
	utils := &ECDSAUtils{}

	prikey := make([]byte, LENOF_PRIVATEKEY, LENOF_PRIVATEKEY)
	rand.Read(prikey)

	pristr := Base64Encode(prikey)
	println("pristr", pristr)

	pubstr, err := utils.PublicKeyFromPrivateString(pristr)
	if err != nil {
		t.Fatal(err)
	}
	println("pubstr", pubstr)
}

func TestSignDataByPrivateString(t *testing.T) {
	data := []byte("Hello World")
	datastr := Base64Encode(data)
	println("datastr", datastr)

	utils := &ECDSAUtils{}
	prikey := make([]byte, LENOF_PRIVATEKEY, LENOF_PRIVATEKEY)
	rand.Read(prikey)
	pristr := Base64Encode(prikey)
	println("pristr", pristr)

	signstr, err := utils.SignDataByPrivateString(pristr, datastr)
	if err != nil {
		t.Fatal(err)
	}
	println("signstr", signstr)
}

func TestVerifySignatureAndDataByPublicString(t *testing.T) {
	data := []byte("Hello World")
	datastr := Base64Encode(data)
	println("datastr", datastr)

	utils := &ECDSAUtils{}
	prikey := make([]byte, LENOF_PRIVATEKEY, LENOF_PRIVATEKEY)
	rand.Read(prikey)
	pristr := Base64Encode(prikey)
	println("pristr", pristr)

	signstr, err := utils.SignDataByPrivateString(pristr, datastr)
	if err != nil {
		t.Fatal(err)
	}
	println("signstr", signstr)

	pubstr, err := utils.PublicKeyFromPrivateString(pristr)
	if err != nil {
		t.Fatal(err)
	}
	println("pubstr", pubstr)

	res, err := utils.VerifySignatureAndDataByPublicString(signstr, pubstr, datastr)
	if err != nil {
		t.Fatal(err)
	}
	println("res", res)

	if res != 1 {
		t.Fatal("Verification Failed.")
	}

	fake := []byte("hello world")
	fakestr := Base64Encode(fake)
	println("fakestr", fakestr)

	res, err = utils.VerifySignatureAndDataByPublicString(signstr, pubstr, fakestr)
	if err != nil {
		t.Fatal(err)
	}
	println("res", res)

	if res != 0 {
		t.Fatal("Verification Failed.")
	}
}

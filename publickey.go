package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

const (
	LENOF_PUBLICKEY  = 2 * LENOF_BIGINT
	SIZEOF_PUBLICKEY = 1 + LENOF_PUBLICKEY
)

type IPublicKey interface {
	Address() IAddress
	Bytes() []byte
	SetBytes([]byte) error
	Crypto() byte
	Data() []byte
	SetData([]byte) error
	String() string
	SetString(string) error
	Verify(ISignable, ISignature) bool
}

type PublicKey struct {
	crypto byte
	x, y   *big.Int
}

func (this *PublicKey) Address() IAddress {
	return &Ripemd160Address{this.crypto, Ripemd160Encrypt(Sha256Encrypt(this.Data()))}
}

func (this *PublicKey) Bytes() (bytes []byte) {
	bytes = make([]byte, SIZEOF_PUBLICKEY)
	bytes[0] = this.crypto
	copy(bytes[1:], this.Data())
	return
}

func (this *PublicKey) SetBytes(bytes []byte) error {
	if len(bytes) != SIZEOF_PUBLICKEY {
		return ERR_SIZEOF_BYTES_INCORRECT
	}

	this.crypto = bytes[0]
	this.SetData(bytes[1:])
	return nil
}

func (this *PublicKey) Crypto() byte {
	return this.crypto
}

func (this *PublicKey) Data() (data []byte) {
	data = make([]byte, LENOF_PUBLICKEY)
	copy(data[:LENOF_BIGINT], this.x.Bytes())
	copy(data[LENOF_BIGINT:], this.y.Bytes())
	return
}

func (this *PublicKey) SetData(bytes []byte) error {
	if len(bytes) != LENOF_PUBLICKEY {
		return ERR_SIZEOF_BYTES_INCORRECT
	}

	this.crypto = CRYPTOTYPEOF_ECDSA256_SHA256_RIPEMD160
	this.x = big.NewInt(0).SetBytes(bytes[:LENOF_BIGINT])
	this.y = big.NewInt(0).SetBytes(bytes[LENOF_BIGINT:])
	return nil
}

func (this *PublicKey) PublicKey() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{elliptic.P256(), this.x, this.y}
}

func (this *PublicKey) String() string {
	return Base64Encode(this.Bytes())
}

func (this *PublicKey) SetString(str string) (err error) {
	data, err := Base64Decode(str)
	if err != nil {
		return
	}

	return this.SetBytes(data)
}

func (this *PublicKey) Verify(signable ISignable, signature ISignature) (ok bool) {
	s, ok := signature.(*Signature)
	if !ok {
		return
	}

	return ecdsa.Verify(this.PublicKey(), Sha256Encrypt(signable.Abstract()), s.R(), s.S())
}

func (this *PublicKey) X() *big.Int {
	return this.x
}

func (this *PublicKey) Y() *big.Int {
	return this.y
}

package ecdsa

import (
	"math/big"
)

const (
	LENOF_SIGNATURE  = 4*LENOF_BIGINT + LENOF_HASH
	SIZEOF_SIGNATURE = 1 + LENOF_SIGNATURE
)

type ISignable interface {
	Abstract() []byte
}

type ISignature interface {
	Address() IAddress
	Bytes() []byte
	SetBytes([]byte) error
	Crypto() byte
	Data() []byte
	SetData([]byte) error
	String() string
	SetString(string) error
	Hash() []byte
	HashString() string
	PublicKey() IPublicKey
	Verify(ISignable) bool
}

type Signature struct {
	crypto     byte
	r, s, x, y *big.Int
	hash       []byte
}

func (this *Signature) Address() IAddress {
	return this.PublicKey().Address()
}

func (this *Signature) Bytes() (bytes []byte) {
	bytes = make([]byte, SIZEOF_SIGNATURE)
	bytes[0] = this.crypto
	copy(bytes[1:], this.Data())
	return
}

func (this *Signature) SetBytes(bytes []byte) error {
	if len(bytes) != SIZEOF_SIGNATURE {
		return ERR_SIZEOF_BYTES_INCORRECT
	}

	this.crypto = bytes[0]
	this.SetData(bytes[1:])
	return nil
}

func (this *Signature) Crypto() byte {
	return this.crypto
}

func (this *Signature) Data() (data []byte) {
	data = make([]byte, LENOF_SIGNATURE)
	copy(data[:LENOF_BIGINT], this.r.Bytes())
	copy(data[LENOF_BIGINT:2*LENOF_BIGINT], this.s.Bytes())
	copy(data[2*LENOF_BIGINT:3*LENOF_BIGINT], this.x.Bytes())
	copy(data[3*LENOF_BIGINT:4*LENOF_BIGINT], this.y.Bytes())
	copy(data[4*LENOF_BIGINT:], this.hash)
	return
}

func (this *Signature) SetData(bytes []byte) error {
	if len(bytes) != LENOF_SIGNATURE {
		return ERR_SIZEOF_BYTES_INCORRECT
	}

	this.r = big.NewInt(0).SetBytes(bytes[:LENOF_BIGINT])
	this.s = big.NewInt(0).SetBytes(bytes[LENOF_BIGINT : 2*LENOF_BIGINT])
	this.x = big.NewInt(0).SetBytes(bytes[2*LENOF_BIGINT : 3*LENOF_BIGINT])
	this.y = big.NewInt(0).SetBytes(bytes[3*LENOF_BIGINT : 4*LENOF_BIGINT])
	this.hash = bytes[4*LENOF_BIGINT:]
	return nil
}

func (this *Signature) Hash() []byte {
	return this.hash
}

func (this *Signature) HashString() string {
	return Base64Encode(this.hash)
}

func (this *Signature) PublicKey() IPublicKey {
	return &PublicKey{this.crypto, this.x, this.y}
}

func (this *Signature) String() string {
	return Base64Encode(this.Bytes())
}

func (this *Signature) SetString(str string) (err error) {
	data, err := Base64Decode(str)
	if err != nil {
		return
	}

	return this.SetBytes(data)
}

func (this *Signature) Verify(signable ISignable) bool {
	return this.PublicKey().Verify(signable, this)
}

func (this *Signature) R() *big.Int {
	return this.r
}

func (this *Signature) S() *big.Int {
	return this.s
}

func (this *Signature) X() *big.Int {
	return this.x
}

func (this *Signature) Y() *big.Int {
	return this.y
}

package ecdsa

import (
	"bytes"
)

type Ripemd160Address struct {
	crypto byte
	data   []byte
}

func (this *Ripemd160Address) Bytes() (b []byte) {
	b = make([]byte, len(this.data)+1)
	b[0] = this.crypto

	copy(b[1:], this.data)
	return
}

func (this *Ripemd160Address) SetBytes(bytes []byte) error {
	if len(bytes) != SIZEOF_RIPEMD160ADDRESS {
		return ERR_SIZEOF_BYTES_INCORRECT
	}

	this.crypto = bytes[0]
	this.SetData(bytes[1:])
	return nil
}

func (this *Ripemd160Address) Crypto() byte {
	return this.crypto
}

func (this *Ripemd160Address) Data() []byte {
	return this.data
}

func (this *Ripemd160Address) SetData(data []byte) (err error) {
	if len(data) != LENOF_RIPEMD160ADDRESS {
		return ERR_SIZEOF_BYTES_INCORRECT
	}

	this.crypto = CRYPTOTYPEOF_ECDSA256_SHA256_RIPEMD160
	this.data = data
	return
}

func (this *Ripemd160Address) String() string {
	return Base64Encode(this.Bytes())
}

func (this *Ripemd160Address) SetString(str string) (err error) {
	data, err := Base64Decode(str)
	if err != nil {
		return
	}

	this.SetBytes(data)
	return
}

func (this *Ripemd160Address) Validate(publicKey IPublicKey) bool {
	return bytes.Compare(publicKey.Address().Data(), this.data) == 0
}

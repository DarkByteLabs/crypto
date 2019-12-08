package crypto

import (
	"bytes"
	"crypto/cipher"
	"io"

	"github.com/DarkByteLabs/crypto/hc128"
)

func NewCipherReader(key Key, r io.Reader) (cr io.Reader, err error) {
	csr := new(cipher.StreamReader)
	var nonce [nonceSize]byte
	nonce, err = readNonce(r)
	csr.S = hc128.New(bytes.NewReader(nonce[:]), key)
	csr.R = r
	cr = csr
	return
}

func NewCipherWriter(key Key, w io.Writer) (cw io.Writer, err error) {
	csw := new(cipher.StreamWriter)
	nonce := generateNonce()
	_, err = w.Write(nonce[:])
	csw.S = hc128.New(bytes.NewReader(nonce[:]), key)
	csw.W = w
	cw = csw
	return
}

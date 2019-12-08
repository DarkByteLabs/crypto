package crypto

import (
	"crypto/rand"
	"io"
)

const nonceSize = 16

func generateNonce() (nonce [nonceSize]byte) {
	rand.Reader.Read(nonce[:])
	return
}

func readNonce(r io.Reader) (nonce [nonceSize]byte, err error) {
	_, err = io.ReadAtLeast(r, nonce[:], len(nonce))
	return
}

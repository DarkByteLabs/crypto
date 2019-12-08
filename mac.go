package crypto

import (
	"io"

	"golang.org/x/crypto/sha3"
)

const macSize = 32

func Mac(key Key, r io.Reader) (mac [macSize]byte, err error) {
	d := sha3.NewShake256()
	_, err = io.Copy(d, key)
	if err != nil {
		return
	}
	_, err = io.Copy(d, r)
	if err != nil {
		return
	}
	_, err = io.ReadAtLeast(d, mac[:], len(mac))
	return
}

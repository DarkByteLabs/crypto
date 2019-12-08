package crypto_test

import (
	"bytes"
	"testing"

	"github.com/DarkByteLabs/crypto"
)

func TestCipher(t *testing.T) {
	pt := []byte{1, 2, 3}
	k := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// check encrypt
	buf := bytes.Buffer{}
	csw, err := crypto.NewCipherWriter(bytes.NewReader(k), &buf)
	if err != nil {
		t.Error(err)
	}
	n, err := csw.Write(pt)
	if err != nil {
		t.Error(err)
	}
	if n != len(pt) {
		t.Errorf("n = %d; want %d", n, len(pt))
	}

	// check ct is not pt
	ct := buf.Bytes()
	var different bool
	for i := range pt {
		if pt[i] != ct[i] {
			different = true
			break
		}
	}
	if !different {
		t.Error("ct unchanged")
	}

	// check decrypt
	csr, err := crypto.NewCipherReader(bytes.NewReader(k), &buf)
	if err != nil {
		t.Error(err)
	}
	pt2 := make([]byte, len(pt))
	n, err = csr.Read(pt2)
	if err != nil {
		t.Error(err)
	}
	if n != len(pt) {
		t.Errorf("n = %d; want %d", n, len(pt))
	}
	for i := range pt {
		if pt[i] != pt2[i] {
			t.Errorf("pt2[%d] = %d; want %d", i, pt2[i], pt[i])
		}
	}
}

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/DarkByteLabs/crypto"
)

func TestMac(t *testing.T) {
	pt := []byte{1, 2, 3}
	k := []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}
	mac, err := crypto.Mac(bytes.NewReader(k), bytes.NewReader(pt))
	if err != nil {
		t.Error(err)
	}
	mac2, err := crypto.Mac(bytes.NewReader(k), bytes.NewReader(pt))
	if err != nil {
		t.Error(err)
	}
	if mac != mac2 {
		t.Error("mac != mac2")
	}
}

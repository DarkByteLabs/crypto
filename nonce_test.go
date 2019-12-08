package crypto_test

import (
	"testing"

	"github.com/DarkByteLabs/crypto"
)

func TestGenerateNonce(t *testing.T) {
	nonce1 := crypto.GenerateNonce()
	nonce2 := crypto.GenerateNonce()
	if nonce1 == nonce2 {
		t.Error("nonce1 == nonce2")
	}
}

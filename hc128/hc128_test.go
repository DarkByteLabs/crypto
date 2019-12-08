package hc128_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/DarkByteLabs/crypto/hc128"
)

func TestXORKeyStream(t *testing.T) {
	var nonce, key [16]byte
	c := hc128.New(bytes.NewReader(nonce[:]), bytes.NewReader(key[:]))
	ref := hc128.New(bytes.NewReader(nonce[:]), bytes.NewReader(key[:]))

	dst, src := make([]byte, 32), make([]byte, 16)
	cmp := make([]byte, 32)
	c.XORKeyStream(dst, src[:2])
	c.XORKeyStream(dst[2:], src[:1])
	c.XORKeyStream(dst[3:], src)
	c.XORKeyStream(dst[19:], src[:13])

	ref.XORKeyStream(cmp, cmp)
	if !bytes.Equal(dst, cmp) {
		t.Fatalf("XORKeyStream failed:\nFound: %s\nExpected: %s", hex.EncodeToString(dst), hex.EncodeToString(cmp))
	}

	dst, src = make([]byte, 15), make([]byte, 16)
	func() {
		defer func() {
			if err := recover(); err == nil {
				t.Fatal("Recover expected error, but no one occured")
			}
		}()
		c.XORKeyStream(dst, src)
	}()
}

// Benchmarks

func BenchmarkXORKeyStream_64B(b *testing.B) {
	var nonce, key [16]byte
	c := hc128.New(bytes.NewReader(nonce[:]), bytes.NewReader(key[:]))

	buf := make([]byte, 64)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkXORKeyStream_1K(b *testing.B) {
	var nonce, key [16]byte
	c := hc128.New(bytes.NewReader(nonce[:]), bytes.NewReader(key[:]))

	buf := make([]byte, 1024)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkXORKeyStream_64K(b *testing.B) {
	var nonce, key [16]byte
	c := hc128.New(bytes.NewReader(nonce[:]), bytes.NewReader(key[:]))

	buf := make([]byte, 64*1024)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

package hc128

// hc128 stream cipher
// based on https://github.com/enceve/crypto/tree/master/hc128

import (
	"crypto/cipher"
	"io"

	"github.com/DarkByteLabs/fastxor"
)

const (
	mod512  uint32 = 0x1FF
	mod1024 uint32 = 0x3FF
)

// New returns a new cipher.Stream implementing the
// HC-128 cipher with the given key and nonce.
func New(nonce, key io.ByteReader) cipher.Stream {
	c := new(streamCipher)
	initialize(nonce, key, &(c.p), &(c.q))
	return c
}

type streamCipher struct {
	p, q      [512]uint32
	ctr       uint32
	keyStream [4]byte
	off       int
}

func (c *streamCipher) XORKeyStream(dst, src []byte) {
	length := len(src)
	if len(dst) < length {
		panic("dst buffer is to small")
	}

	if c.off > 0 {
		left := 4 - c.off
		if left > length {
			left = length
		}
		for i, v := range c.keyStream[c.off : c.off+left] {
			dst[i] = src[i] ^ v
		}
		src = src[left:]
		dst = dst[left:]
		length -= left
		c.off += left
		if c.off == 4 {
			c.off = 0
		}
	}

	n := length - (length % 4)
	for i := 0; i < n; i += 4 {
		k := genKeyStream(&(c.ctr), &(c.p), &(c.q))
		dst[i] = src[i] ^ byte(k)
		dst[i+1] = src[i+1] ^ byte(k>>8)
		dst[i+2] = src[i+2] ^ byte(k>>16)
		dst[i+3] = src[i+3] ^ byte(k>>24)
	}

	length -= n
	if length > 0 {
		k := genKeyStream(&(c.ctr), &(c.p), &(c.q))
		c.keyStream[0] = byte(k)
		c.keyStream[1] = byte(k >> 8)
		c.keyStream[2] = byte(k >> 16)
		c.keyStream[3] = byte(k >> 24)
		c.off += fastxor.Bytes(dst[n:], src[n:], c.keyStream[:])
	}
}

func initialize(nonce, key io.ByteReader, p, q *[512]uint32) {
	var tmp [1280]uint32

	for i := 0; i < 16; i++ {
		j := i >> 2
		k := 8 * (i % 4)
		b, err := key.ReadByte()
		if err != nil {
			panic(err)
		}
		tmp[j] |= uint32(b) << k
		b, err = nonce.ReadByte()
		if err != nil {
			panic(err)
		}
		tmp[8+j] |= uint32(b) << k
	}
	copy(tmp[4:8], tmp[0:4])
	copy(tmp[12:16], tmp[8:12])

	// expand key and nonce with the f1 and f2 functions
	// (2.2 http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf)
	var f2, f1 uint32
	for i := 16; i < 1280; i++ {
		f1, f2 = tmp[i-15], tmp[i-2]
		f1 = ((f1 >> 7) | (f1 << 25)) ^ ((f1 >> 18) | (f1 << 14)) ^ (f1 >> 3)
		f2 = ((f2 >> 17) | (f2 << 15)) ^ ((f2 >> 19) | (f2 << 13)) ^ (f2 >> 10)
		tmp[i] = f1 + f2 + tmp[i-7] + tmp[i-16] + uint32(i)
	}
	copy(p[:], tmp[256:(256+512)])
	copy(q[:], tmp[768:(768+512)])

	// do 1024 iterations for initialization
	var ctr uint32
	for i := range p {
		p[i] = genKeyStream(&ctr, p, q)
	}
	for i := range q {
		q[i] = genKeyStream(&ctr, p, q)
	}
}

func genKeyStream(counter *uint32, p, q *[512]uint32) uint32 {
	var r, t0, t1, t2, t3 uint32
	ctr := *counter

	j := ctr & mod512
	if ctr < 512 {
		t0 = p[(j-3)&mod512]
		t1 = p[(j-10)&mod512]
		t2 = p[(j-511)&mod512]
		t3 = p[(j-12)&mod512]

		t0 = ((t0 >> 10) | (t0 << 22))
		t1 = ((t1 >> 8) | (t1 << 24))
		t2 = ((t2 >> 23) | (t2 << 9))
		p[j] += (t0 ^ t2) + t1

		t0 = t3 & 0xff
		t1 = 256 + (t3>>16)&0xff
		r = (q[t0] + q[t1]) ^ p[j]
	} else {
		t0 = q[(j-3)&mod512]
		t1 = q[(j-10)&mod512]
		t2 = q[(j-511)&mod512]
		t3 = q[(j-12)&mod512]

		t0 = ((t0 << 10) | (t0 >> 22))
		t1 = ((t1 << 8) | (t1 >> 24))
		t2 = ((t2 << 23) | (t2 >> 9))
		q[j] += (t0 ^ t2) + t1

		t0 = t3 & 0xff
		t1 = 256 + (t3>>16)&0xff
		r = p[t0] + p[t1] ^ q[j]
	}

	*counter = (ctr + 1) & mod1024
	return r
}

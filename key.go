package crypto

import "io"

type Key interface {
	io.ByteReader
	io.Reader
}

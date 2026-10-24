package cryptoengine

import "io"

type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b, err := RandomBytes(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, b)
	return len(p), nil
}

// RandReader exposes the active engine's CSPRNG as an io.Reader.
var RandReader io.Reader = randReader{}

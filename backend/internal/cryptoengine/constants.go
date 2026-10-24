package cryptoengine

const (
	SHA256Size    = 32
	AES256KeySize = 32
	GCMNonceSize  = 12
	GCMTagSize    = 16
	X25519KeySize = 32
	HKDFMaxOutput = 255 * SHA256Size
)

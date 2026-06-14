package utility

// BigEndianBytes converts an int to its big-endian byte representation.
// This is used for encoding RSA public key exponents in JWKS (RFC 7517).
func BigEndianBytes(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var bytes []byte
	for v := e; v > 0; v >>= 8 {
		bytes = append([]byte{byte(v & 0xff)}, bytes...)
	}
	return bytes
}

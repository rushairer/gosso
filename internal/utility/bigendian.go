package utility

import "errors"

// ErrNegativeInput is returned when BigEndianBytes receives a negative value.
var ErrNegativeInput = errors.New("bigendian: negative input not supported")

// BigEndianBytes converts an int to its big-endian byte representation.
// This is used for encoding RSA public key exponents in JWKS (RFC 7517).
// Returns an error on negative input (RSA exponents are always positive).
func BigEndianBytes(e int) ([]byte, error) {
	if e == 0 {
		return []byte{0}, nil
	}
	if e < 0 {
		return nil, ErrNegativeInput
	}
	var bytes []byte
	for v := e; v > 0; v >>= 8 {
		bytes = append([]byte{byte(v & 0xff)}, bytes...)
	}
	return bytes, nil
}

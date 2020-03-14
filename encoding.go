package rsacrypto

import "encoding/hex"

// A common interface used to transform data between bytes and string.
// All base64 encodings implement this interface.
type Encoding interface {
	EncodeToString(b []byte) string
	DecodeString(s string) ([]byte, error)
}

// A hex encoding struct, like the official base64 encodings.
type hexEncoding struct {}

func (hexEncoding) EncodeToString(b []byte) string {
	return hex.EncodeToString(b)
}

func (hexEncoding) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

var HexEncoding = hexEncoding{}

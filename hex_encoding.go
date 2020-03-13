package rsacrypto

import "encoding/hex"

// A hex encoding struct, like the official base64 encodings.
type hexEncoding struct {}

func (hexEncoding) EncodeToString(b []byte) string {
	return hex.EncodeToString(b)
}

func (hexEncoding) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

var HexEncoding = hexEncoding{}

package rsacrypto_go

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
)

// Parse rsa public key from DER (binary) data.
//		PKIX, PKCS1 formats would try one by one.
//		About DER, @see https://en.wikipedia.org/wiki/X.690#DER_encoding .
func ParseDERPublicKey(der []byte) (key *rsa.PublicKey, err error) {
	// Try PKIX format.
	key1, err1 := x509.ParsePKIXPublicKey(der)
	if err1 == nil {
		return key1.(*rsa.PublicKey), nil
	}

	// Log the first error.
	errs := make([]error, 0, 2)
	errs = append(errs, err1)

	// Try PKCS1 format.
	key2, err2 := x509.ParsePKCS1PublicKey(der)
	if err2 == nil {
		return key2, nil
	}

	// Log the second error.
	errs = append(errs, err2)

	b := strings.Builder{}
	for _, e := range errs {
		b.WriteString(e.Error())
		b.WriteString("\n")
	}
	return nil, errors.New(b.String())
}

// Parse rsa public key from a base64 string.
func ParseBase64PublicKey(keyBase64 string, encoding *base64.Encoding) (key *rsa.PublicKey, err error) {
	if encoding == nil {
		encoding = base64.StdEncoding
	}

	der, err := encoding.DecodeString(keyBase64)
	if err != nil {
		return nil, err
	}

	return ParseDERPublicKey(der)
}


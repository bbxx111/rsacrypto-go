package rsacrypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

type EncrypterOpts interface{}

type RSAEncrypter struct {
	publicKey *rsa.PublicKey
	opts      EncrypterOpts
}

func NewRSAEncrypter(publicKey *rsa.PublicKey, opts EncrypterOpts) *RSAEncrypter {
	return &RSAEncrypter{
		publicKey: publicKey,
		opts:      opts,
	}
}

func (enc *RSAEncrypter) Encrypt(plain []byte) (cipher []byte, err error) {
	// RSA algorithm has a limit to the plain message,
	// so we need to divide the message into chunks first,
	// then encrypt every chunk.
	// @see https://en.wikipedia.org/wiki/RSA_(cryptosystem)
	if enc.opts == nil {
		// PKCS1v15
		limit := enc.publicKey.Size() - 11
		chunks := split(plain, limit)
		buffer := bytes.NewBufferString("")
		for _, chunk := range chunks {
			encryptedChunk, err := rsa.EncryptPKCS1v15(rand.Reader, enc.publicKey, chunk)
			if err != nil {
				return nil, err
			}
			buffer.Write(encryptedChunk)
		}
		return buffer.Bytes(), nil
	} else {
		switch opts := enc.opts.(type) {
		case *rsa.OAEPOptions:
			limit := enc.publicKey.Size() - opts.Hash.Size()*2 - 2
			chunks := split(plain, limit)
			buffer := bytes.NewBufferString("")
			for _, chunk := range chunks {
				encryptedChunk, err := rsa.EncryptOAEP(opts.Hash.New(), rand.Reader, enc.publicKey, chunk, opts.Label)
				if err != nil {
					return nil, err
				}
				buffer.Write(encryptedChunk)
			}
			return buffer.Bytes(), nil
		default:
			return nil, errors.New("rsacrypto: invalid options for encrypt")
		}
	}
}

type DecrypterOpts interface{}

type RSADecrypter struct {
	privateKey *rsa.PrivateKey
	opts       DecrypterOpts
}

func NewRSADecrypter(privateKey *rsa.PrivateKey, opts DecrypterOpts) *RSADecrypter {
	return &RSADecrypter{
		privateKey: privateKey,
		opts:       opts,
	}
}

func (dec *RSADecrypter) Decrypt(cipher []byte) (plain []byte, err error) {
	limit := dec.privateKey.Size()
	chunks := split(cipher, limit)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decryptedChunk, err := dec.privateKey.Decrypt(rand.Reader, chunk, dec.opts)
		if err != nil {
			return nil, err
		}
		buffer.Write(decryptedChunk)
	}
	return buffer.Bytes(), nil
}

type DefaultSignerOpts struct {
	Hash crypto.Hash
}

func (opts *DefaultSignerOpts) HashFunc() crypto.Hash {
	return opts.Hash
}

type RSASigner struct {
	privateKey *rsa.PrivateKey
	opts       crypto.SignerOpts
}

func NewRSASigner(privateKey *rsa.PrivateKey, opts crypto.SignerOpts) *RSASigner {
	return &RSASigner{
		privateKey: privateKey,
		opts:       opts,
	}
}

func (sig *RSASigner) Sign(data []byte) (sign []byte, err error) {
	h := sig.opts.HashFunc().New()
	h.Write(data)
	digest := h.Sum(nil)

	return sig.privateKey.Sign(rand.Reader, digest, sig.opts)
}

type RSAVerifier struct {
	publicKey *rsa.PublicKey
	opts      crypto.SignerOpts
}

func NewRSAVerifier(publicKey *rsa.PublicKey, opts crypto.SignerOpts) *RSAVerifier {
	return &RSAVerifier{
		publicKey: publicKey,
		opts:      opts,
	}
}

func (ver *RSAVerifier) Verify(data []byte, sign []byte) (err error) {
	h := ver.opts.HashFunc().New()
	h.Write(data)
	digest := h.Sum(nil)

	if pssOpts, ok := ver.opts.(*rsa.PSSOptions); ok {
		return rsa.VerifyPSS(ver.publicKey, pssOpts.Hash, digest, sign, pssOpts)
	}
	return rsa.VerifyPKCS1v15(ver.publicKey, ver.opts.HashFunc(), digest, sign)
}

func split(buffer []byte, limit int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buffer)/limit+1)
	for len(buffer) >= limit {
		chunk, buffer = buffer[:limit], buffer[limit:]
		chunks = append(chunks, chunk)
	}
	if len(buffer) > 0 {
		chunks = append(chunks, buffer[:len(buffer)])
	}
	return chunks
}

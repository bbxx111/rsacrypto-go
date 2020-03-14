package rsacrypto

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"errors"
)

type MarshalFunc func(v interface{}) ([]byte, error)

// A wrapper for encrypt and verify sign.
type RSAPublicKey struct {
	publicKey     *rsa.PublicKey
	encrypterOpts EncrypterOpts
	marshalFunc   MarshalFunc // Used to encrypt an object, could be one of json.Marshal/xml.Marshal/yaml.Marshal .
	signerOpts    crypto.SignerOpts
}

func NewRSAPublicKey() *RSAPublicKey {
	return &RSAPublicKey{
		publicKey:     nil,
		encrypterOpts: nil,
		marshalFunc:   json.Marshal,
		signerOpts:    nil,
	}
}

func (k *RSAPublicKey) SetKey(key *rsa.PublicKey) *RSAPublicKey {
	k.publicKey = key
	return k
}

func (k *RSAPublicKey) SetEncodedKey(encodedKey string, encoding Encoding) (*RSAPublicKey, error) {
	key, err := ParseEncodedPublicKey(encodedKey, encoding)
	if err != nil {
		return nil, err
	}

	k.publicKey = key
	return k, nil
}

func (k *RSAPublicKey) SetEncrypterOpts(opts EncrypterOpts) *RSAPublicKey {
	k.encrypterOpts = opts
	return k
}

func (k *RSAPublicKey) SetMarshalFunc(marshal MarshalFunc) *RSAPublicKey {
	k.marshalFunc = marshal
	return k
}

func (k *RSAPublicKey) SetSignerOpts(opts crypto.SignerOpts) *RSAPublicKey {
	k.signerOpts = opts
	return k
}

func (k *RSAPublicKey) SetSignerHash(hash crypto.Hash) *RSAPublicKey {
	k.signerOpts = &DefaultSignerOpts{Hash: hash}
	return k
}

func (k *RSAPublicKey) Encrypt(plain []byte) (cipher []byte, err error) {
	if k.publicKey == nil {
		return nil, errors.New("rsacrypto: invalid public key")
	}
	return NewRSAEncrypter(k.publicKey, k.encrypterOpts).Encrypt(plain)
}

func (k *RSAPublicKey) EncryptAndEncode(plain []byte, encoding Encoding) (cipher string, err error) {
	b, err := k.Encrypt(plain)
	if err != nil {
		return "", err
	}
	return encoding.EncodeToString(b), nil
}

// Encrypt a object.
func (k *RSAPublicKey) EncryptObject(object interface{}) (cipher []byte, err error) {
	b, err := k.marshalFunc(object)
	if err != nil {
		return nil, err
	}

	return k.Encrypt(b)
}

func (k *RSAPublicKey) EncryptObjectAndEncode(object interface{}, encoding Encoding) (cipher string, err error) {
	b, err := k.EncryptObject(object)
	if err != nil {
		return "", err
	}
	return encoding.EncodeToString(b), nil
}

func (k *RSAPublicKey) Verify(data []byte, sign []byte) error {
	if k.signerOpts == nil {
		return errors.New("rsacrypto: invalid signer options for verifier")
	}
	return NewRSAVerifier(k.publicKey, k.signerOpts).Verify(data, sign)
}

func (k *RSAPublicKey) DecodeAndVerify(data []byte, sign string, encoding Encoding) error {
	b, err := encoding.DecodeString(sign)
	if err != nil {
		return err
	}
	return k.Verify(data, b)
}

type UnmarshalFunc func(data []byte, v interface{}) error

// A wrapper for decrypt and sign.
type RSAPrivateKey struct {
	privateKey    *rsa.PrivateKey
	decrypterOpts DecrypterOpts
	unmarshalFunc UnmarshalFunc // Used to decrypt an object, could be one of json.Unmarshal/xml.Unmarshal/yaml.Unmarshal .
	signerOpts    crypto.SignerOpts
}

func NewRSAPrivateKey() *RSAPrivateKey {
	return &RSAPrivateKey{
		privateKey:    nil,
		decrypterOpts: nil,
		unmarshalFunc: json.Unmarshal,
		signerOpts:    nil,
	}
}

func (k *RSAPrivateKey) SetKey(key *rsa.PrivateKey) *RSAPrivateKey {
	k.privateKey = key
	return k
}

func (k *RSAPrivateKey) SetEncodedKey(encodedKey string, encoding Encoding) (*RSAPrivateKey, error) {
	key, err := ParseEncodedPrivateKey(encodedKey, encoding)
	if err != nil {
		return nil, err
	}

	k.privateKey = key
	return k, nil
}

func (k *RSAPrivateKey) SetDecrypterOpts(opts DecrypterOpts) *RSAPrivateKey {
	k.decrypterOpts = opts
	return k
}

func (k *RSAPrivateKey) SetUnmarshalFunc(unmarshal UnmarshalFunc) *RSAPrivateKey {
	k.unmarshalFunc = unmarshal
	return k
}

func (k *RSAPrivateKey) SetSignerOpts(opts crypto.SignerOpts) *RSAPrivateKey {
	k.signerOpts = opts
	return k
}

func (k *RSAPrivateKey) SetSignerHash(hash crypto.Hash) *RSAPrivateKey {
	k.signerOpts = &DefaultSignerOpts{Hash: hash}
	return k
}

func (k *RSAPrivateKey) Decrypt(cipher []byte) (plain []byte, err error) {
	if k.privateKey == nil {
		return nil, errors.New("rsacrypto: invalid private key")
	}
	return NewRSADecrypter(k.privateKey, k.decrypterOpts).Decrypt(cipher);
}

func (k *RSAPrivateKey) DecodeAndDecrypt(cipher string, encoding Encoding) (plain []byte, err error) {
	b, err := encoding.DecodeString(cipher)
	if err != nil {
		return nil, err
	}
	return k.Decrypt(b)
}

func (k *RSAPrivateKey) DecryptToObject(cipher []byte, object interface{}) error {
	plain, err := k.Decrypt(cipher)
	if err != nil {
		return err
	}
	return k.unmarshalFunc(plain, object)
}

func (k *RSAPrivateKey) DecodeAndDecryptToObject(cipher string, encoding Encoding, object interface{}) error {
	b, err := encoding.DecodeString(cipher)
	if err != nil {
		return err
	}
	return k.DecryptToObject(b, object)
}

func (k *RSAPrivateKey) Sign(data []byte) (sign []byte, err error) {
	if k.signerOpts == nil {
		return nil, errors.New("rsacrypto: invalid signer options for signer")
	}
	return NewRSASigner(k.privateKey, k.signerOpts).Sign(data)
}

func (k *RSAPrivateKey) SignAndEncode(data []byte, encoding Encoding) (sign string, err error) {
	b, err := k.Sign(data)
	if err != nil {
		return "", err
	}
	return encoding.EncodeToString(b), nil
}
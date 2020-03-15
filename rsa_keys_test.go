package rsacrypto

import (
	"crypto"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRSAPublicKey_EncryptAndEncode(t *testing.T) {
	testData := []string{
		``,
		`A short message`,
		`This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。`,
		`{"json": "This is a json message", "int": 99, "null": null, "chinese": "这是一段中文。"}`,
		`<xml><data>hello xml world!</data></xml>`,
	}

	for _, plain := range testData {
		for _, key := range testKeys {
			pubKey, err := NewRSAPublicKey().SetEncodedKey(key.PublicKey, nil)
			assert.Nil(t, err)
			privKey, err := NewRSAPrivateKey().SetEncodedKey(key.PrivateKey, nil)
			assert.Nil(t, err)

			// Test with base64.StdEncoding.
			cipher, err := pubKey.EncryptAndEncode([]byte(plain), base64.StdEncoding)
			assert.Nil(t, err)
			decrypted, err := privKey.DecodeAndDecrypt(cipher, base64.StdEncoding)
			assert.Nil(t, err)
			assert.Equal(t, plain, string(decrypted))

			// Test with base64.URLEncoding.
			cipher, err = pubKey.EncryptAndEncode([]byte(plain), base64.URLEncoding)
			assert.Nil(t, err)
			decrypted, err = privKey.DecodeAndDecrypt(cipher, base64.URLEncoding)
			assert.Nil(t, err)
			assert.Equal(t, plain, string(decrypted))

			// Test with HexEncoding.
			cipher, err = pubKey.EncryptAndEncode([]byte(plain), HexEncoding)
			assert.Nil(t, err)
			decrypted, err = privKey.DecodeAndDecrypt(cipher, HexEncoding)
			assert.Nil(t, err)
			assert.Equal(t, plain, string(decrypted))


			if len(plain) > 0 {
				cipher, err = pubKey.EncryptAndEncode([]byte(plain), base64.StdEncoding)
				assert.Nil(t, err)
				decrypted, err = privKey.DecodeAndDecrypt(cipher, HexEncoding)
				assert.NotNil(t, err)
				assert.Nil(t, decrypted)
				decrypted, err = privKey.DecodeAndDecrypt(cipher, base64.URLEncoding)
				assert.NotNil(t, err)
				assert.Nil(t, decrypted)
			}
		}
	}
}

func TestRSAPublicKey_EncryptObjectAndEncode(t *testing.T) {
	type userT struct {
		Mobile   string `json:"mobile"`
		UserName string `json:"userName"`
		IdCard   string `json:"idCard"`
		DeviceId string `json:"deviceId"`
	}

	u := userT{
		Mobile:   "12345678901",
		UserName: "My Test",
		IdCard:   "987654321098765432",
		DeviceId: "di_135792468",
	}
	key := testKeys[0]

	pubKey, err := NewRSAPublicKey().SetEncodedKey(key.PublicKey, nil)
	assert.Nil(t, err)
	privKey, err := NewRSAPrivateKey().SetEncodedKey(key.PrivateKey, nil)
	assert.Nil(t, err)

	cipher, err := pubKey.EncryptObjectAndEncode(u, base64.StdEncoding)
	assert.Nil(t, err)
	t.Logf("cipher: %s", cipher)

	decrypted := userT{}
	err = privKey.DecodeAndDecryptToObject(cipher, base64.StdEncoding, &decrypted)
	assert.Nil(t, err)

	assert.Equal(t, u.Mobile, decrypted.Mobile)
	assert.Equal(t, u.UserName, decrypted.UserName)
	assert.Equal(t, u.IdCard, decrypted.IdCard)
	assert.Equal(t, u.DeviceId, decrypted.DeviceId)
}

func TestRSAPrivateKey_SignAndEncode(t *testing.T) {
	testData := []string{
		``,
		`A short message`,
		`This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。
This is a very very long message. 这是一段很长很长的消息。This is a very very long message. 这是一段很长很长的消息。`,
		`{"json": "This is a json message", "int": 99, "null": null, "chinese": "这是一段中文。"}`,
		`<xml><data>hello xml world!</data></xml>`,
	}

	for _, plain := range testData {
		for _, key := range testKeys {
			pubKey, err := NewRSAPublicKey().SetEncodedKey(key.PublicKey, nil)
			assert.Nil(t, err)
			privKey, err := NewRSAPrivateKey().SetEncodedKey(key.PrivateKey, nil)
			assert.Nil(t, err)

			// Test with SHA1 and HexEncoding.
			sign, err := privKey.SetSignerHash(crypto.SHA1).SignAndEncode([]byte(plain), HexEncoding)
			assert.Nil(t, err)
			t.Logf("sign(len: %d): %s", len(sign), sign)
			err = pubKey.SetSignerHash(crypto.SHA1).DecodeAndVerify([]byte(plain), sign, HexEncoding)
			assert.Nil(t, err)

			// Test with SHA256 and base64.StdEncoding.
			sign, err = privKey.SetSignerHash(crypto.SHA256).SignAndEncode([]byte(plain), base64.StdEncoding)
			assert.Nil(t, err)
			t.Logf("sign(len: %d): %s", len(sign), sign)
			err = pubKey.SetSignerHash(crypto.SHA256).DecodeAndVerify([]byte(plain), sign, base64.StdEncoding)
			assert.Nil(t, err)

			sign, err = privKey.SetSignerHash(crypto.SHA256).SignAndEncode([]byte(plain), base64.StdEncoding)
			assert.Nil(t, err)
			err = pubKey.SetSignerHash(crypto.SHA1).DecodeAndVerify([]byte(plain), sign, base64.StdEncoding)
			assert.NotNil(t, err)
			err = pubKey.SetSignerHash(crypto.SHA1).DecodeAndVerify([]byte(plain), sign, HexEncoding)
			assert.NotNil(t, err)
		}
	}
}

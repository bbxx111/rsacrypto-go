package rsacrypto

import (
	"crypto"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRSAEncrypter_Encrypt(t *testing.T) {
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
			pub, err := ParseBase64PublicKey(key.PublicKey, nil)
			assert.Nil(t, err)

			cipher, err := NewRSAEncrypter(pub, nil).Encrypt([]byte(plain))
			assert.Nil(t, err)
			t.Logf("cipher: %s", base64.StdEncoding.EncodeToString(cipher))

			priv, err := ParseBase64PrivateKey(key.PrivateKey, nil)
			assert.Nil(t, err)

			decrypted, err := NewRSADecrypter(priv, nil).Decrypt(cipher)
			assert.Nil(t, err)
			assert.Equal(t, plain, string(decrypted))
		}
	}
}

func TestRSADecrypter_Decrypt(t *testing.T) {
	const (
		msg = `This is a message. 这是一段消息。`

		cipher = `JNSakhRSuKtktiZejyYXqOaULZI6PH9HdrLgfPC0m+H8ebWQnLCB3o85DP1jHb4UTKTiL/8Ml1hlOvUuZuvAOFYymNfraVfmcGCB9zzs2A24tK3qQNxtpWMWPhM4ZemZvoYFMkLiy22POFRRaCDf65AUAmgsQWuEH9qccqurRXA=`

		//		publicKey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZ7ACjrC9Cx5zimQ8q6NiO3X8t
		//sZbqtpFwJtNcj9jblQuRLmyYx1yWBi9N5JpFX1106UdycFGCZI6KjiEy8AMg9/5/
		//mPSYqPxCwGsQQv+7jIJ8AE3WEKr5RBgIjdr8ANE/R4SlAolZKHYP24Tcnm04EcZj
		//KBbVJGzNPXcAsDDpywIDAQAB`

		privateKey = `MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJnsAKOsL0LHnOKZ
Dyro2I7dfy2xluq2kXAm01yP2NuVC5EubJjHXJYGL03kmkVfXXTpR3JwUYJkjoqO
ITLwAyD3/n+Y9Jio/ELAaxBC/7uMgnwATdYQqvlEGAiN2vwA0T9HhKUCiVkodg/b
hNyebTgRxmMoFtUkbM09dwCwMOnLAgMBAAECgYBHFMbCzwxQQZCA0IBBp6ACceV+
e4mfQMpvSW7ISyGxXeYmmJLMBx0JpzeHOC/KI50sFWLKRXZOyhNNhw9rz40RoDUD
lL67Hjce9mqIn266E375xOTv6eQ8V7FLClFBzXSTg+oxHerpZDEF5UH9MVaKiHda
LxWkdD6RMPknDizt4QJBAMpOcRY2xYVkX2DST5V7o6pWz4RxM0Vkj+5eMI0f4svR
AlylRCqlZLT5DqLpuxEoYCJj7Xr53GXl3DzWGm3Ns7sCQQDCxhwujwhpbx/mE3Yh
3qfHkVxqagpLjHa3jYxaL8i3n8ayGc9lgR0EjNAs+fLF3iYGZJxyYu/QGpu1rH73
6NkxAkAYo8EmQXmBK55qPnMu86YVYwlXSipCc2MMVzB2n8GRrV0qR36r6wT+/a6I
rQr5pf8/cQhFiBUN3Bcc2b7STNFtAkA119hQkp/LrbmOu9CLWmbdR3TZwgioi+MB
qPKkt9Lv2A5wi6wGrmOcL2UZGdugEWJHoCaThIAw8jobRd0voUHxAkEAg8F19wnC
Nbmu9mtwXBhXFSfnwucXO3kklMlb1ZRbJnqoltWSB60njjF9Iw+aSekBkqCC3t3V
O8wjYqIOxrtt9g==`
	)

	//pub, err := ParseBase64PublicKey(publicKey, nil)
	//assert.Nil(t, err)
	//encrypted, err := NewRSAEncrypter(pub, nil).Encrypt([]byte(msg))
	//assert.Nil(t, err)
	//t.Logf("cipher: %s", base64.StdEncoding.EncodeToString(encrypted))

	priv, err := ParseBase64PrivateKey(privateKey, nil)
	assert.Nil(t, err)
	cipherBytes, err := base64.StdEncoding.DecodeString(cipher)
	assert.Nil(t, err)
	decrypted, err := NewRSADecrypter(priv, nil).Decrypt([]byte(cipherBytes))
	assert.Nil(t, err)
	assert.Equal(t, msg, string(decrypted))
}

func TestRSASigner_Sign(t *testing.T) {
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

	for _, msg := range testData {
		for _, key := range testKeys {
			priv, err := ParseBase64PrivateKey(key.PrivateKey, nil)
			assert.Nil(t, err)

			signer := NewRSASigner(priv, &DefaultSignerOpts{Hash: crypto.SHA1})
			sign, err := signer.Sign([]byte(msg))
			assert.Nil(t, err)
			t.Logf("sign: %s", base64.StdEncoding.EncodeToString(sign))

			pub, err := ParseBase64PublicKey(key.PublicKey, nil)
			assert.Nil(t, err)

			verifier := NewRSAVerifier(pub, &DefaultSignerOpts{Hash: crypto.SHA1})
			err = verifier.Verify([]byte(msg), sign)
			assert.Nil(t, err)
		}
	}
}

func TestRSAVerifier_Verify(t *testing.T) {
	const (
		msg = `Hello world!世界你好！`

		sign = `FWYb8nidardAExJa8ynvSnHMprgubYy3q45C3qqGC0G4X1m+2Q6z6y91lIvpWOb8t/DWurrxwn9p3DppX+zig1iykCwyR0ucA2Dc3PD6+Rf7Gl0eAMWVDrBKHA/OfHT1IdtozpAqVO4luMJwXmAjVR1zcS9ENQUnySwxpVvwMQQ=`

		publicKey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDxpR9dSyOKXqfnoGxHchJxfX/W
NYTBALm6trLLcqpdoTu73B9fvNVPkc45S/pc1yxzrFGSDwrNwqPl4J3HTPF2hPzY
PaYs9ZrYQppBZ7NVTRNBjV41zzZRZ1EmpSfVMLKkHKMvREpJIfp00ky1YHRm52Ee
V4jtLN1KSC8BhLRslQIDAQAB`

		privateKey = `MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAPGlH11LI4pep+eg
bEdyEnF9f9Y1hMEAubq2sstyql2hO7vcH1+81U+RzjlL+lzXLHOsUZIPCs3Co+Xg
ncdM8XaE/Ng9piz1mthCmkFns1VNE0GNXjXPNlFnUSalJ9UwsqQcoy9ESkkh+nTS
TLVgdGbnYR5XiO0s3UpILwGEtGyVAgMBAAECgYEA4Lp0+dmIWwX+1x5NtQA0gNF7
UycAqFHZaPjCPQ0NvffVyrdDglDmfJKYHJc5ZqBCWe1XCyPsI0GyFXaYpaI8J/OS
uX8Pr5p+LwLPCKQJ9dWUiTsY0NtxOdIhSy4tH3vy3amio4U1PHUOVaBUKz8YDuCv
due07Cb9gRB9qtf/5L0CQQD6Q0//CZFzcyEAh4eSVi85hqBQHV2+FCMUo4dRT0Yh
s8xhZrvZA+yfUq8++Wt/Te/lBo7zQEgkGFSrMHI0H0s3AkEA9y88K71FFn7juu4y
5GtO6be4h/Zv5EQrCoSJ4RCcw32ZVbcZ6JTYGMftB5nr5wIf5KtVEzHeDYNMBT23
olukkwJBAKOvvTXxmyno5nADNUAYkMDOdjKQUo0NfLh2EP60nAlVIVufp0PVFkJL
AYZt+sqEPmEM/hjKNaUuKMrjX/8JbNcCQQCpsBWAeVg6TzWKmAb74+ayb1sQi07Y
xys89yuoA716PnjK7P2uOq/2oxjHBRV66mx2kF/A45Tqdd30IyAzJvJdAkBZvmTS
rf1l8YeyGbJ7gh74KxaLsVlX9jS75t1S1PqkdFk8jvBRm+kyIdBlJsQYXbFPW1nH
iTcboX4T250is9bI`
	)

	//priv, err := ParseBase64PrivateKey(privateKey, nil)
	//assert.Nil(t, err)
	//signer := NewRSASigner(priv, &DefaultSignerOpts{Hash: crypto.SHA256})
	//signed, err := signer.Sign([]byte(msg))
	//assert.Nil(t, err)
	//t.Logf("sign: %s", base64.StdEncoding.EncodeToString(signed))

	pub, err := ParseBase64PublicKey(publicKey, nil)
	assert.Nil(t, err)

	signBytes, err := base64.StdEncoding.DecodeString(sign)
	assert.Nil(t, err)

	verifier := NewRSAVerifier(pub, &DefaultSignerOpts{Hash: crypto.SHA256})
	err = verifier.Verify([]byte(msg), signBytes)
	assert.Nil(t, err)
}
# rsacrypto-go

The *rsacrypto* is a RSA encryption and decryption tool based on official golang library.

Key features:
- Easy to use.
- Support encryption and decryption of **large** data.

## Encryption and Decryption of Large Data

About data size limit of RSA algorithm, see https://en.wikipedia.org/wiki/RSA_(cryptosystem).

This library support RSA encryption and decryption of large by dividing data into chunks.


## Encrypt with RSA Public Key

1. Encrypt

```go
package example

import (
    "crypto"
    "encoding/base64"
    "rsacrypto"
)

const (
    publicKeyBase64 = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwe7ST4M16O/B8tBCZ0bwrrcZP
                       H+5UCaEbEnOnRjQ+TfnfdEN3IhpA1+bgjDF/2sa83ONnzWaVOl+urB1gdCdUA+FJ
                       22ZgnvynEuafxh9R5dk7X9GRkin6xRN7ABrY0rubMFpNChc0vgm0+r8HHXrTo7pM
                       0QdIdM4TfhczB4SaBQIDAQAB`

    plain = `This is a test plain message.`
)

func ExampleEncrypt() ([]byte, error) {
    pubKey, err := NewRSAPublicKey().SetEncodedKey(publicKeyBase64, base64.StdEncoding)
    if err != nil {
        return nil, err
    }
    return pubKey.Encrypt([]byte(plain))
}
```

2. Encrypt and Encode

```go
package example

import (
    "crypto"
    "encoding/base64"
    "rsacrypto"
)

const (
    publicKeyBase64 = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwe7ST4M16O/B8tBCZ0bwrrcZP
                       H+5UCaEbEnOnRjQ+TfnfdEN3IhpA1+bgjDF/2sa83ONnzWaVOl+urB1gdCdUA+FJ
                       22ZgnvynEuafxh9R5dk7X9GRkin6xRN7ABrY0rubMFpNChc0vgm0+r8HHXrTo7pM
                       0QdIdM4TfhczB4SaBQIDAQAB`

    plain = `This is a test plain message.`
)

func ExampleEncryptAndEncode() (string, error) {
    pubKey, err := NewRSAPublicKey().SetEncodedKey(publicKeyBase64, base64.StdEncoding)
    if err != nil {
        return "", err
    }
    return pubKey.EncryptAndEncode([]byte(plain), base64.StdEncoding)
}
```

## Decrypt with a RSA Private Key

1. Decrypt

```go
package example

import (
    "crypto"
    "encoding/base64"
    "rsacrypto"
)

const (
    privateKeyBase64 = `MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJnsAKOsL0LHnOKZ
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

    cipher = `JNSakhRSuKtktiZejyYXqOaULZI6PH9HdrLgfPC0m+H8ebWQnLCB3o85DP1jHb4UTKTiL/8Ml1hlOvUuZuvAOFYymNfraVfmcGCB9zzs2A24tK3qQNxtpWMWPhM4ZemZvoYFMkLiy22POFRRaCDf65AUAmgsQWuEH9qccqurRXA=`
)

func ExampleDecrypt() ([]byte, error) {
    cipherBytes, err := base64.StdEncoding.DecodeString(cipher)
    if err != nil {
        return nil, err
    }
    privKey, err := NewRSAPrivateKey().SetEncodedKey(privateKeyBase64, base64.StdEncoding)
    if err != nil {
        return nil, err
    }
    // plain is the decrypted byte data.
    return privKey.Decrypt(cipherBytes)
}
```

2. Decode and Decrypt

```go
package example

import (
    "crypto"
    "encoding/base64"
    "rsacrypto"
)

const (
    privateKeyBase64 = `MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJnsAKOsL0LHnOKZ
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

    cipher = `JNSakhRSuKtktiZejyYXqOaULZI6PH9HdrLgfPC0m+H8ebWQnLCB3o85DP1jHb4UTKTiL/8Ml1hlOvUuZuvAOFYymNfraVfmcGCB9zzs2A24tK3qQNxtpWMWPhM4ZemZvoYFMkLiy22POFRRaCDf65AUAmgsQWuEH9qccqurRXA=`
)

func ExampleDecodeAndDecrypt() ([]byte, error) {
    privKey, err := NewRSAPrivateKey().SetEncodedKey(privateKeyBase64, base64.StdEncoding)
    if err != nil {
        return nil, err
    }
    return privKey.DecodeAndDecrypt(cipher, base64.StdEncoding)
}
```

## Sign with RSA Private Key

1. Sign

```go
package example

import (
    "crypto"
    "encoding/base64"
    "rsacrypto"
)

const (
    privateKeyBase64 = `MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJnsAKOsL0LHnOKZ
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

    data = `This is a test data.`
)

func ExampleSign() ([]byte, error) {
    privKey, err := NewRSAPrivateKey().SetEncodedKey(privateKeyBase64, base64.StdEncoding)
    if err != nil {
        return nil, err
    }
    // sign is a byte array.
    return privKey.SetSignerHash(crypto.SHA1).Sign([]byte(data))
}
```

2. Sign and Encode

```go
package example

import (
    "crypto"
    "encoding/base64"
    "rsacrypto"
)

const (
    privateKeyBase64 = `MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJnsAKOsL0LHnOKZ
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

    data = `This is a test data.`
)

func ExampleSignAndEncode() (string, error) {
    privKey, err := NewRSAPrivateKey().SetEncodedKey(privateKeyBase64, base64.StdEncoding)
    if err != nil {
        return "", err
    }
    // sign is encoded by HexEncoding.
    return privKey.SetSignerHash(crypto.SHA1).SignAndEncode([]byte(data), HexEncoding)
}
```

## Verify Sign with RSA Public Key

1. Verify Sign

```go
package example

import (
    "crypto"
    "encoding/base64"
    "rsacrypto"
)

const (
    publicKeyBase64 = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDxpR9dSyOKXqfnoGxHchJxfX/W
                       NYTBALm6trLLcqpdoTu73B9fvNVPkc45S/pc1yxzrFGSDwrNwqPl4J3HTPF2hPzY
                       PaYs9ZrYQppBZ7NVTRNBjV41zzZRZ1EmpSfVMLKkHKMvREpJIfp00ky1YHRm52Ee
                       V4jtLN1KSC8BhLRslQIDAQAB`

		data = `Hello world!世界你好！`

		sign = `FWYb8nidardAExJa8ynvSnHMprgubYy3q45C3qqGC0G4X1m+2Q6z6y91lIvpWOb8t/DWurrxwn9p3DppX+zig1iykCwyR0ucA2Dc3PD6+Rf7Gl0eAMWVDrBKHA/OfHT1IdtozpAqVO4luMJwXmAjVR1zcS9ENQUnySwxpVvwMQQ=`
)

func ExampleVerifySign() error {
    signBytes, err := base64.StdEncoding.DecodeString(sign)
    if err != nil {
        return err
    }
    pubKey, err := NewRSAPublicKey().SetEncodedKey(publicKeyBase64, base64.StdEncoding)
    if err != nil {
        return err
    }
    return pubKey.SetSignerHash(crypto.SHA256).Verify([]byte(data), signBytes)
}
```

2. Decode and Verify Sign

```go
package example

import (
    "crypto"
    "encoding/base64"
    "rsacrypto"
)

const (
    publicKeyBase64 = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDxpR9dSyOKXqfnoGxHchJxfX/W
                       NYTBALm6trLLcqpdoTu73B9fvNVPkc45S/pc1yxzrFGSDwrNwqPl4J3HTPF2hPzY
                       PaYs9ZrYQppBZ7NVTRNBjV41zzZRZ1EmpSfVMLKkHKMvREpJIfp00ky1YHRm52Ee
                       V4jtLN1KSC8BhLRslQIDAQAB`

    data = `Hello world!世界你好！`

    sign = `FWYb8nidardAExJa8ynvSnHMprgubYy3q45C3qqGC0G4X1m+2Q6z6y91lIvpWOb8t/DWurrxwn9p3DppX+zig1iykCwyR0ucA2Dc3PD6+Rf7Gl0eAMWVDrBKHA/OfHT1IdtozpAqVO4luMJwXmAjVR1zcS9ENQUnySwxpVvwMQQ=`
)

func ExampleDecodeAndVerifySign() error {
    pubKey, err := NewRSAPublicKey().SetEncodedKey(publicKeyBase64, base64.StdEncoding)
    if err != nil {
        return err
    } 
    return pubKey.SetSignerHash(crypto.SHA256).DecodeAndVerify([]byte(data), sign, HexEncoding)
}
```

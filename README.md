# rsacrypto-go

## Encrypt with RSA Public Key

1. Encrypt

```go
const (
    publicKeyBase64 = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwe7ST4M16O/B8tBCZ0bwrrcZP
                       H+5UCaEbEnOnRjQ+TfnfdEN3IhpA1+bgjDF/2sa83ONnzWaVOl+urB1gdCdUA+FJ
                       22ZgnvynEuafxh9R5dk7X9GRkin6xRN7ABrY0rubMFpNChc0vgm0+r8HHXrTo7pM
                       0QdIdM4TfhczB4SaBQIDAQAB`

    plain = `This is a test plain message.`
)

if pubKey, err := NewRSAPublicKey().SetEncodedKey(publicKeyBase64, base64.StdEncoding); err != nil {
    // cipher is the encrypted byte data.
    cipher, err := pubKey.Encrypt(plain)
}
```

2. Encrypt and Encode

```go
const (
    publicKeyBase64 = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwe7ST4M16O/B8tBCZ0bwrrcZP
                       H+5UCaEbEnOnRjQ+TfnfdEN3IhpA1+bgjDF/2sa83ONnzWaVOl+urB1gdCdUA+FJ
                       22ZgnvynEuafxh9R5dk7X9GRkin6xRN7ABrY0rubMFpNChc0vgm0+r8HHXrTo7pM
                       0QdIdM4TfhczB4SaBQIDAQAB`

    plain = `This is a test plain message.`
)

if pubKey, err := NewRSAPublicKey().SetEncodedKey(publicKeyBase64, base64.StdEncoding); err != nil {
    // cipher is the encrypted and encoded string data.
    cipher, err := pubKey.EncryptAndEncode(plain, base64.StdEncoding)
}
```

## Decrypt with a RSA Private Key

1. Decrypt

```go
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

cipherBytes, err := base64.StdEncoding.DecodeString(cipher)
if err != nil {
    if privKey, err := NewRSAPrivateKey().SetEncodedKey(privateKeyBase64, base64.StdEncoding); err != nil {
        // plain is the decrypted byte data.
        plain, err := privKey.Decrypt(cipherBytes)
    }
}
```

2. Decode And Decrypt

```go
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

if privKey, err := NewRSAPrivateKey().SetEncodedKey(privateKeyBase64, base64.StdEncoding); err != nil {
    // plain is the decoded and decrypted byte data.
    plain, err := privKey.DecodeAndDecrypt(cipher, base64.StdEncoding)
}
```

## Sign with RSA Private Key

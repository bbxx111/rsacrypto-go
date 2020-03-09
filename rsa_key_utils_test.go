package rsacrypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	testKeys = []struct {
		PrivateKey string
		PublicKey  string
	}{
		{
			// PKCS8
			PrivateKey: `MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDnp8e2lwL1LHkn
71k4vSNRK2A/N45AWE/gQhghN+huFXUFpUHGpqGrOo/sKEZJA309QqMnW8yQUdnG
dCoP1Pv6J1V9l5icGq6IRs1QowtCKVF/XRM6ItaJDd9LpE6HYWJC1hKcTypjsgHy
v/zZMThrsOnOrZP+GOrp/lQwsKre6YwH+FTn0+MaLf79FLOdcwtVclybolkZCrCR
flo0rLjlPQtXPnJgW+WCcDmn+FCEtD/kcVz3BP63+0DoF01f+Umt3vMLG0dnq0K6
0IFyi9Nv9CBYmfyqRVwcvLsfNnEfnYcOWR/0Tl4nxeLBlemqE8UE9msR+CZAWmMN
vgz+BO5nAgMBAAECggEAL5S5o5pO5DbXR8mUpN/MYj6rjTCHClZZSbGprSEDn6DO
oXM5GGlfaYEk0JfRH+wUjEGkq0/iq330Yhu4C/puKwprN9msYdvlH16Ti02B4XwF
HkjqyxUexZXQ2IOOEaaB/UJlHi/wf/uvBMJEWAQRF6WF0Iq8jANoNNmlRz7ySciA
c4em/+uqPt+fpngg8vDyfnsPHA3uSZDs1St/3hVvMbEsoODXUkLoJNUg3p8MI00x
O9GKuQ0Mtv5D6OWeBPZD2EBwPO0xhuQ0Ke821R7DJ3xmqSkhqjXClT8kJDMCEM+1
h20WfXnFiZ19LMrsjf79S/SlAi6kKGfIk5QlPAhdYQKBgQD+x79XsYC0DogGc2x4
xvyxZBk//cR20zS3AuX6cCe0b6HViwkC2/3JbQcBjy4SYi3/cOXhBDf59V7poRcl
Mk7GxAuEztpqCC6xUGxuMva+wtp55MPvTMEtrWZROm98c/BsTOaOh0FvZ/MJN76X
F2ZVOalkevZKgiWlzylPwKtbtwKBgQDow7EAQ2CqD+RNNCNJZ3TvjGjY7gbEEBsx
QjaGuWhLi8FQ4NCxqM00X9xlsADAqsgLJNphEJsyNlDmFGco1T8VOjCvYj4xkEqp
++2AxCA15U56qZ9qxlW+XL5INNvVFdaiFaDIfbln3fKOfQpIr2c3jyrZ64xqleh/
LqFaBRVi0QKBgQCW/VupJbmne6EjaY4UOaERo8fPA55F6T8pYl9WvtbY+PtIqWAK
wMMzdxia1Pax0FuAMbEaXDysNr0r6drkoV7MLuzApTINepHpZUcNO8i9Ho8JhAiW
Lb+iSUwEwYPGlpMaK6zLNN8TneALS2z479YmlciMks6ZM24KSK4r5HvpGwKBgBTQ
Cq+fVrFeImfU1aLmoUoaH/Xlsq0tU4EgDogVZAH9SRfWQlLgaRjZyXc+OZMAskps
zSoIthfTS4CHKoI4Lx/SyC+mdTExWbvBTwdIgijPjCjjqeF+QoR2/nyuXUm8Xii4
DlxfAYkMC3g6LgU5ydzp7Eb4DOIq7VMR9FN8SOFBAoGAWtn9lz94luTVgvssZteR
WIq8Jbb0UtlLoDY6tehr79YY9Cib/67pe2Dgkxr8wJD8yYeoJ6DYySLflp6k0bmJ
Y+b3HOGS1E0E8Rxrhaw8Kmdfd/Ky3YoPT0ovAw4/wlzM18RgXXNWPoJjfa4XiEiQ
YXXqAqkJr2fpfbyXkcKaA34=`,

			// PKIX
			PublicKey: `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA56fHtpcC9Sx5J+9ZOL0j
UStgPzeOQFhP4EIYITfobhV1BaVBxqahqzqP7ChGSQN9PUKjJ1vMkFHZxnQqD9T7
+idVfZeYnBquiEbNUKMLQilRf10TOiLWiQ3fS6ROh2FiQtYSnE8qY7IB8r/82TE4
a7Dpzq2T/hjq6f5UMLCq3umMB/hU59PjGi3+/RSznXMLVXJcm6JZGQqwkX5aNKy4
5T0LVz5yYFvlgnA5p/hQhLQ/5HFc9wT+t/tA6BdNX/lJrd7zCxtHZ6tCutCBcovT
b/QgWJn8qkVcHLy7HzZxH52HDlkf9E5eJ8XiwZXpqhPFBPZrEfgmQFpjDb4M/gTu
ZwIDAQAB`,
		},
		{
			// PKCS1
			PrivateKey: `MIICXQIBAAKBgQCl5bTWSePhktf8c5aPQDODWr2+AejpLPG9PAcf4uaVWiR1NQ3J
yc5Cq2APJKsn5mo0tLVGV8H/96p160I1nWymWcSg16lzttQ/0A1YQn/BVVdzvotC
2nneGJIJOH2Bh6kcyS8FFWpjovTK2Wq2rTgIvTLIOf9jAYhkyhwC1yIAvwIDAQAB
AoGAI8Gya/uKG+0IE5ggS+j1EWtF+UW1G0j+I6DkEjnYJDnFIOQaADO4esMwVaM8
JsHxg0GtzqcMn+yUN41I/IBdUdaO9cbk9G9rZMS3TeqxyCrIo0ZpZ0aSF66IyHX1
O+DKlU7WGJx3BHEP2tePepHKmshECl/PycQZAeiYe+l+X+ECQQDC8DyYQzTjc9VB
j3bxNKTK4B8P2yo/dJD7E4hfWx2KiCeMW65xk9893M/gffy50jCOzyUpNP9us5Lr
JZc/dhBhAkEA2dy2kOwyjKmtE3Xwk81ZAgddQPdqsf6Lteufnfn83fUbYSMgg4fr
FsAjga1NO8m6u7ewqSQIwpAh8AcOqnglHwJBAKEV/DymbLH4KiV+8/7mTbcH9SMZ
LJQ7MwMHZQ3HMWYklOm7aS+ZzkREj9MmyQyU0GNycXbXwKwt4B5Ide+PFIECQH8Q
Mk5949GUWIRkIgciGgqL3wC4DLt5WWSl4vdRSQDvJqPVx+3OxPcE4vCL8eKv+j/n
l5pekNlhFNoYU55q6kMCQQCtdgBen09WxmiBgiaJttv7T8e9Q7llMBAj7gWijj02
m81/wa2/C2UOa6NZteWaY12bHc7wmsJn7GMxX8PyoQwN`,

			// PKIX
			PublicKey: `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCl5bTWSePhktf8c5aPQDODWr2+
AejpLPG9PAcf4uaVWiR1NQ3Jyc5Cq2APJKsn5mo0tLVGV8H/96p160I1nWymWcSg
16lzttQ/0A1YQn/BVVdzvotC2nneGJIJOH2Bh6kcyS8FFWpjovTK2Wq2rTgIvTLI
Of9jAYhkyhwC1yIAvwIDAQAB`,
		},
	}
)

func TestParseBase64PublicKey(t *testing.T) {
	for _, key := range testKeys {
		pub, err := ParseBase64PublicKey(key.PublicKey, nil)
		assert.Nil(t, err)
		assert.NotNil(t, pub)
	}
}

func TestParseBase64PrivateKey(t *testing.T) {
	for _, key := range testKeys {
		priv, err := ParseBase64PrivateKey(key.PrivateKey, nil)
		assert.Nil(t, err)
		assert.NotNil(t, priv)

		pub, err := ParseBase64PublicKey(key.PublicKey, nil)
		assert.Equal(t, pub.E, priv.E)
		assert.Equal(t, pub.N, priv.N)
	}
}

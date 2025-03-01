package main

import (
	"fmt"
	"testing"

	"go.mozilla.org/pkcs7"
)

func Test_value(t *testing.T) {
	rawMessage := []byte(`
MIAGCSqGSIb3DQEHAqCAMIACAQExADALBgkqhkiG9w0BBwGggDCCAXkwggEgoAMC
AQICBgGVPZIizTAKBggqhkjOPQQDAjBCMRYwFAYDVQQGEw1Vbml0ZWQgU3RhdGVz
MRMwEQYDVQQKEwpDdW11bG9jaXR5MRMwEQYDVQQDEwptYW5hZ2VtZW50MB4XDTI1
MDIyNTE0NDU0MloXDTI2MDIyNDA5NDE0NFowRjEaMBgGA1UEAwwRZGlkaWVyLWRl
dmljZS0wMDExEjAQBgNVBAoMCVRoaW4gRWRnZTEUMBIGA1UECwwLVGVzdCBEZXZp
Y2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATwSjNE/7AJZEtrXW2CP2LSLlcl
wDyh4YwHmpwDhnTCm+ZxeeXBUcUARcFXOtdmxMset9CgMQl1Fjw255dISpqiMAoG
CCqGSM49BAMCA0cAMEQCICapYBWyzrDU36IVEtyOfdlDA0bW9HE3pwHz2X9LAgl1
AiAD0naayxieH0RVE1vJtdD3iCJHrzLNM3Eff2gNOhuzJAAAMQAAAAAAAAA=
`)
	b, err := base64Decode(rawMessage)
	if err != nil {
		t.Errorf("Failed to decode base64 message")
	}

	p7, err := pkcs7.Parse(b)
	if err != nil {
		t.Errorf("Failed to parse pkcs7 message")
	}

	fmt.Printf("%s", pemCert(p7.Certificates[0].Raw))
}

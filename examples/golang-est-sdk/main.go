package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/thales-e-security/estclient"
)

//
// base 64 encoding
//

const (
	base64LineLength = 64
)

// minInt returns the smallest value of x and y.
func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// hardWrap wraps a string precisely to the limit, breaking words
// as necessary. The resulting string will always end with a line
// break.
func hardWrap(text string, limit int) string {
	var b strings.Builder

	for j := 0; j < len(text)-1; j += limit {
		upperBound := minInt(j+limit, len(text))
		b.WriteString(text[j:upperBound])
		b.WriteString("\n")
	}

	return b.String()
}

// toBase64 converts bytes to base64, wrapped at 64 chars
func toBase64(data []byte) string {
	return hardWrap(base64.StdEncoding.EncodeToString(data), base64LineLength)
}

const csrPEMBlockType = "CERTIFICATE REQUEST"
const certPEMBlockType = "CERTIFICATE"

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// convert DER to PEM format
func pemCSR(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    csrPEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    certPEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func main() {

	id := os.Getenv("DEVICE_ID")
	secret := os.Getenv("DEVICE_OTP")
	if len(os.Args) >= 3 {
		id = os.Args[1]
		secret = os.Args[2]
	}
	if id == "" || secret == "" {
		panic("Missing required arguments. <DEVICE_ID> <OTP>")
	}

	host := strings.TrimPrefix(os.Getenv("C8Y_HOST"), "https://")
	fmt.Printf("host=%s, id=%s, secret=%s", host, id, secret)

	client := estclient.NewEstClient(host + ":443")
	// estclient.NewEstClientWithOptions("host", estclient.ClientOptions{

	// 	TLSTrustAnchor: &x509.Certificate{

	// 	},
	// })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	panicOnError(err)

	template := x509.CertificateRequest{Subject: pkix.Name{CommonName: id}}

	reqBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	panicOnError(err)

	req, err := x509.ParseCertificateRequest(reqBytes)
	panicOnError(err)

	fmt.Printf("CSR (DER): %s\n", toBase64(req.Raw))
	fmt.Printf("CSR (PEM): \n%s\n", pemCSR(req.Raw))

	// Enroll with EST CA
	authData := estclient.AuthData{ID: &id, Secret: &secret}
	cert, err := client.SimpleEnroll(authData, req)
	panicOnError(err)

	fmt.Printf("Device Certificate (DER): %x\n", toBase64(cert.Raw))
	fmt.Printf("Device Certificate (PEM): \n%s\n", pemCert(req.Raw))
}

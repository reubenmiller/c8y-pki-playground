package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/globalsign/est"
	"github.com/thin-edge/golang-globalsign-sdk/keyutil"
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

func createCSR(id string, key any) (*x509.CertificateRequest, error) {
	template := x509.CertificateRequest{Subject: pkix.Name{CommonName: id}}
	reqBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}
	req, err := x509.ParseCertificateRequest(reqBytes)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func showCert(cert *x509.Certificate) {
	fmt.Printf("Device Certificate (DER): %x\n", toBase64(cert.Raw))
	fmt.Printf("Device Certificate (PEM): \n%s\n", pemCert(cert.Raw))
}

func banner(section string) {
	fmt.Println("\n\n---------------------------------------------------------------")
	fmt.Println(section)
	fmt.Println("---------------------------------------------------------------")
}

func GetTedgeSetting(k string) (string, error) {
	value, err := exec.Command("tedge", "config", "get", k).CombinedOutput()
	return string(bytes.TrimSpace(value)), err
}

func RunTedgeCommand(cmds ...string) error {
	cmd := exec.Command("tedge", cmds...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func init() {
	slog.SetLogLoggerLevel(slog.LevelInfo)
}

type EnrollmentOptions struct {
	Host     string
	DeviceID string
	Password string
}

func Enroll(opts EnrollmentOptions) error {
	client := est.Client{
		Host:     opts.Host,
		Username: opts.DeviceID,
		Password: opts.Password,
	}

	key, err := LoadDevicePrivateKeyFromFile()
	if err != nil {
		return err
	}

	req, err := createCSR(opts.DeviceID, key)
	if err != nil {
		return err
	}

	fmt.Printf("CSR (DER): %s\n", toBase64(req.Raw))
	fmt.Printf("CSR (PEM): \n%s\n", pemCSR(req.Raw))

	// Enroll with EST CA
	banner("Requesting initial Certificate")
	cert, err := client.Enroll(context.Background(), req)
	if err != nil {
		return err
	}

	showCert(cert)
	WriteCertificateToFile(cert)
	return nil
}

func WriteCertificateToFile(cert *x509.Certificate) error {
	slog.Info("Writing certificate to file")
	certPath, err := GetTedgeSetting("device.cert_path")
	if err != nil {
		return err
	}

	os.Chmod(certPath, 0644)
	return os.WriteFile(certPath, pemCert(cert.Raw), 0644)
}

func LoadDeviceCertificateFromFile() (*x509.Certificate, error) {
	certPath, err := GetTedgeSetting("device.cert_path")
	if err != nil {
		return nil, err
	}
	contents, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(contents))
	cert, _ := x509.ParseCertificate(block.Bytes)
	return cert, nil
}

func LoadDevicePrivateKeyFromFile() (any, error) {
	keyPath, err := GetTedgeSetting("device.key_path")
	if err != nil {
		return nil, err
	}

	slog.Info("Reading private key from file.", "path", keyPath)
	key, err := keyutil.PrivateKeyFromFile(keyPath)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func RenewCertificate(opts EnrollmentOptions) (*x509.Certificate, error) {
	// Read existing certificate
	existingCert, err := LoadDeviceCertificateFromFile()
	if err != nil {
		panic(fmt.Errorf("could not load x509 certificate from file. %s", err))
	}

	// Create CSR
	key, err := LoadDevicePrivateKeyFromFile()
	if err != nil {
		panic(fmt.Errorf("could not load private key from file. %s", err))
	}
	req, err := createCSR(existingCert.Subject.CommonName, key)
	if err != nil {
		return nil, err
	}

	banner("Renewing Certificate")
	reenrollClient := est.Client{
		// FIX: A client changed was required to support the local proxy via http
		Host: "http://127.0.0.1:8001/c8y",
		// Experiment: Try manual password
		// AdditionalHeaders: map[string]string{
		// 	"Authorization": "Bearer " + opts.Password,
		// },
		Certificates: []*x509.Certificate{
			existingCert,
		},
	}
	cert, err := reenrollClient.Reenroll(context.Background(), req)
	if err != nil {
		return nil, err
	}

	showCert(cert)
	err = WriteCertificateToFile(cert)
	return cert, err
}

// Main
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
	slog.Info("Configuration.", "host", host, "id", id, "secret", secret)

	enrollOptions := EnrollmentOptions{
		Host:     host,
		DeviceID: id,
		Password: secret,
	}

	shouldEnroll := false

	if shouldEnroll {
		banner("Enrolling device")
		if err := Enroll(enrollOptions); err != nil {
			panic(err)
		}

		if err := RunTedgeCommand("cert", "show"); err != nil {
			panic(err)
		}

		if err := RunTedgeCommand("reconnect", "c8y"); err != nil {
			panic(err)
		}
	}

	banner("Renewing Certificate")
	opts := EnrollmentOptions{
		Host: enrollOptions.Host,
	}
	if _, err := RenewCertificate(opts); err != nil {
		panic(err)
	}
	// Reconnect (to verify the certificate)
	if err := RunTedgeCommand("reconnect", "c8y"); err != nil {
		panic(err)
	}
}

func base64Decode(src []byte) ([]byte, error) {
	dec := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(dec, src)
	if err != nil {
		return nil, err
	}
	return dec[:n], nil
}

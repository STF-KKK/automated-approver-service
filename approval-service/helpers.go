package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/rs/zerolog"
)

// ECDSASignature holds the ASN.1 structure for ECDSA signatures (r, s)
type ECDSASignature struct {
	R, S *big.Int
}

// Encode ECDSA (r, s) signature
func signIntent(
	privateKey *ecdsa.PrivateKey,
	intent []byte,
) ([]byte, error) {
	hash := sha256.Sum256(intent)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	sig := ECDSASignature{
		R: r,
		S: s,
	}

	return asn1.Marshal(sig)
}

// Helper function to pad a byte slice to 32 bytes
func padTo32Bytes(b []byte) []byte {
	if len(b) == 32 {
		return b
	}

	// Create a new slice of 32 bytes and copy the original bytes to the rightmost part
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func verifySignature(message, publicKey, signature []byte) error {
	pk, err := x963PublicKeyToECDSAPublicKey(publicKey)
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write(message)
	digest := h.Sum(nil)

	if !ecdsa.VerifyASN1(pk, digest, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func x963PublicKeyToECDSAPublicKey(publicKey []byte) (*ecdsa.PublicKey, error) {
	if len(publicKey) != 65 {
		return nil, fmt.Errorf(
			"public key len expected 65, got %d. Base64 key: %s",
			len(publicKey), base64.StdEncoding.EncodeToString(publicKey),
		)
	}
	if publicKey[0] != 4 {
		return nil, fmt.Errorf("not an uncompressed public key")
	}

	x := new(big.Int).SetBytes(publicKey[1:33])
	y := new(big.Int).SetBytes(publicKey[33:65])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid public key")
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, fmt.Errorf("point at infinity cannot be a public key")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// selfSignedTLSCertificateFromSeed creates a TLS cert from a seed
func selfSignedTLSCertificateFromSeed(
	logger zerolog.Logger,
	seed []byte,
	secretManager SecretsManagerAPI,
) (tls.Certificate, error) {
	name := "System approval test server"
	privateKey := ed25519.NewKeyFromSeed(seed)
	startTime := time.Date(2024, 10, 21, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    startTime,
		NotAfter:     endTime,
	}

	x509Certificate, err := x509.CreateCertificate(
		rand.Reader,
		tpl,
		tpl,
		privateKey.Public(),
		privateKey,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	asn1Bytes, err := x509.MarshalPKIXPublicKey(
		privateKey.Public().(ed25519.PublicKey),
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	tlsPubKey := base64.StdEncoding.EncodeToString(asn1Bytes)
	logger.Info().
		Str("tls_public_key", tlsPubKey).
		Msg("TLS public key of the server")

	err = secretManager.PutSecret(
		tlsPubKey,
		"sandbox-approval-tls-public-key",
	)

	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{x509Certificate},
		PrivateKey:  privateKey,
	}, nil
}

package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Server struct {
	echo   *echo.Echo
	logger zerolog.Logger

	cfg ServerConfig

	tlsCert    *tls.Certificate
	privateKey *ecdsa.PrivateKey
}

func newServer(cfg ServerConfig) (*Server, error) {
	echoInstance := echo.New()
	echoInstance.HideBanner = true

	lgr := log.Logger.With().
		Str("component", "system-approver-test").
		Logger()

	if err := setup(echoInstance, lgr); err != nil {
		return nil, err
	}

	var err error
	var secretManager SecretsManagerAPI
	switch cfg.SecretManager {
	case SecretsManagerAWS:

		secretManager, err = NewSecretClientAWS(
			getRegion(),
			zerolog.New(os.Stdout).With().Timestamp().Caller().Logger(),
		)
		if err != nil {
			return nil, err
		}
	case SecretsManagerLocal:
		secretManager = NewSecretClientLocal()
	default:
		return nil, fmt.Errorf("secret manager type %s is not supported", cfg.SecretManager)
	}

	if cfg.SecretManager != SecretsManagerLocal {
		cfg.PrivateKey, err = secretManager.GetSecret("sandbox-approval-tls-private-key")
		if err != nil {
			return nil, fmt.Errorf("failed to get tls private key: %s", err)
		}

		cfg.TLSPrivateKeySeed, err = secretManager.GetSecret("sandbox-approval-key-seed")
		if err != nil {
			return nil, fmt.Errorf("failed to get key seed: %s", err)
		}
	}

	var tlsCert *tls.Certificate
	if cfg.TLSPrivateKeySeed != "" {
		decodedSeed, err := cfg.TLSPrivateKeySeedDecoded()
		if err != nil {
			return nil, fmt.Errorf("failed to decode tls private key: %s", err)
		}

		cert, err := selfSignedTLSCertificateFromSeed(lgr, decodedSeed, secretManager)
		if err != nil {
			return nil, fmt.Errorf("failed to create tls certificate: %s", err)
		}
		tlsCert = &cert
	}

	privateKeyDer, err := cfg.PrivateKeyDecoded()
	if err != nil {
		return nil, fmt.Errorf("failed to decode pk: %s", err)
	}
	privateKey, err := x509.ParseECPrivateKey(privateKeyDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pk: %s", err)
	}

	publicKey := base64.StdEncoding.EncodeToString(
		getPublicKey(privateKey),
	)
	fmt.Printf("signature_verification_key\":\"%s\"\n", publicKey)

	err = secretManager.PutSecret(
		publicKey,
		"sandbox-approval-signature-verification-key",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to put aws secret sandbox-approval-signature-verification-key: %s", err)
	}

	server := Server{
		cfg:        cfg,
		echo:       echoInstance,
		logger:     lgr,
		privateKey: privateKey,
		tlsCert:    tlsCert,
	}

	// Routes
	echoInstance.POST("/confirm", server.Confirm)
	echoInstance.GET("/public-key", server.GetPublicKey)

	return &server, nil
}

type ServerConfig struct {
	Port int `json:"port"`

	// ASN.1 DER encoded private key
	PrivateKey string `json:"private_key"`

	// TLSPrivateKeySeed A base64 32-byte seed key which will be used for
	// TLS certificate creation
	TLSPrivateKeySeed string `json:"tls_private_key_seed"`

	SecretManager string `json:"secret_manager"`
}

func (s ServerConfig) PrivateKeyDecoded() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.PrivateKey)
}

func (s ServerConfig) TLSPrivateKeySeedDecoded() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.TLSPrivateKeySeed)
}

// setup registers the handlers for and adds loggers/middlewares to
// common.echo.Echo
func setup(
	echoInstance *echo.Echo,
	l zerolog.Logger,
) error {
	// Only log errors, not successful requests
	echoInstance.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:    true,
		LogStatus: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			// Only log request details if there's an error
			if v.Error != nil {
				l.Err(v.Error).
					Str("time", v.StartTime.Format(time.RFC3339)).
					Str("remote_ip", c.RealIP()).
					Str("host", c.Request().Host).
					Str("method", c.Request().Method).
					Str("uri", v.URI).
					Str("user_agent", c.Request().UserAgent()).
					Int("status", v.Status).
					Float64("latency", v.Latency.Seconds()).
					Msg("request")
			}
			return nil
		},
	}))
	echoInstance.Use(middleware.Recover())
	echoInstance.Use(errorMiddleware())

	return nil
}

func (s *Server) Serve() error {
	// Running TLS if cert is available
	if s.tlsCert != nil {
		server := http.Server{
			Addr:      fmt.Sprintf(":%d", s.cfg.Port),
			Handler:   s.echo, // set Echo as handler
			TLSConfig: newTLSConfig(*s.tlsCert),
		}

		// TLS server started, no need to log port
		err := server.ListenAndServeTLS("", "")
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	}

	// Server started, no need to log port
	return s.echo.Start(fmt.Sprintf(":%d", s.cfg.Port))
}

type SignOperationRequest struct {
	EnrichedIntent []byte
	MPASignature   []byte
}

func (s SignOperationRequest) Validate() error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.EnrichedIntent, validation.Required),
		validation.Field(&s.MPASignature, validation.Required),
	)
}

type SignOperationResponse struct {
	Confirmed bool
	Signature []byte
}

func (s *Server) Confirm(c echo.Context) error {
	var body SignOperationRequest
	if err := c.Bind(&body); err != nil {
		return err
	}

	if err := body.Validate(); err != nil {
		return err
	}

	var genericIntent GenericIntent
	if err := json.Unmarshal(body.EnrichedIntent, &genericIntent); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Testing only 'transfer' or 'call smart contract' operations for now
	if genericIntent.OperationType != "transfer" && genericIntent.OperationType != "call smart contract" && genericIntent.OperationType != "deploy contract" && genericIntent.OperationType != "sign raw transaction" {
		s.logger.Warn().
			Str("operationType", genericIntent.OperationType).
			Msg("unsupported operation type requested")
		return echo.NewHTTPError(http.StatusNotImplemented, "only 'transfer', 'call smart contract', 'deploy contract', and 'sign raw transaction' are supported")
	}

	intent := genericIntent.Intent
	signature, err := signIntent(s.privateKey, intent)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Handle different operation types and print pretty intent
	switch genericIntent.OperationType {
	case "transfer":
		var transferIntent TransferIntent
		if err := json.Unmarshal(genericIntent.Intent, &transferIntent); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		if len(transferIntent.DestinationAmounts) == 0 {
			return echo.NewHTTPError(
				http.StatusBadRequest,
				"empty destination amounts, op %s "+transferIntent.OperationID,
			)
		}

		// Pretty print the transfer intent
		intentJSON, _ := json.MarshalIndent(transferIntent, "", "  ")
		fmt.Printf("\n=== TRANSFER INTENT ===\n%s\n", string(intentJSON))

	case "call smart contract":
		var callContractIntent CallContractIntent
		if err := json.Unmarshal(genericIntent.Intent, &callContractIntent); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		// Pretty print the contract call intent
		intentJSON, _ := json.MarshalIndent(callContractIntent, "", "  ")
		fmt.Printf("\n=== CONTRACT CALL INTENT ===\n%s\n", string(intentJSON))

	case "deploy contract":
		var deployContractIntent DeployContractIntent
		if err := json.Unmarshal(genericIntent.Intent, &deployContractIntent); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		// Pretty print the contract deploy intent
		intentJSON, _ := json.MarshalIndent(deployContractIntent, "", "  ")
		fmt.Printf("\n=== CONTRACT DEPLOY INTENT ===\n%s\n", string(intentJSON))

	case "sign raw transaction":
		var rawTxIntent SignRawTransactionIntent
		if err := json.Unmarshal(genericIntent.Intent, &rawTxIntent); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		// Pretty print the raw transaction intent
		intentJSON, _ := json.MarshalIndent(rawTxIntent, "", "  ")
		fmt.Printf("\n=== SIGN RAW TRANSACTION INTENT ===\n%s\n", string(intentJSON))
	}

	// Print signature information
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("\n=== SIGNATURE (APPROVED) ===\n")
	fmt.Printf("Signature (Base64): %s\n", signatureB64)
	fmt.Printf("Signature (Hex): %x\n", signature)
	fmt.Printf("========================\n\n")

	return c.JSON(
		http.StatusOK,
		&SignOperationResponse{
			Confirmed: true,
			Signature: signature,
		},
	)
}

type GetPublicKey struct {
	PublicKey []byte `json:"public_key"`
}

func (s *Server) GetPublicKey(c echo.Context) error {
	return c.JSON(http.StatusOK, &GetPublicKey{
		PublicKey: getPublicKey(s.privateKey),
	})
}

func getPublicKey(privKey *ecdsa.PrivateKey) []byte {
	// Extract the public key
	publicKey := privKey.PublicKey

	// Convert the public key coordinates (X and Y) to 32-byte slices
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()

	// Make sure X and Y are exactly 32 bytes long
	xBytesPadded := padTo32Bytes(xBytes)
	yBytesPadded := padTo32Bytes(yBytes)

	// Concatenate the X and Y coordinates to form the 65-byte public key
	// MPA only accepts that format for now
	return slices.Concat(
		[]byte{0x04}, // Prefix 0x04 (indicating the key is uncompressed)
		xBytesPadded,
		yBytesPadded,
	)
}

func newTLSConfig(cert tls.Certificate) *tls.Config {
	tlsConfig := tls.Config{
		MinVersion: uint16(tls.VersionTLS12),
		MaxVersion: uint16(tls.VersionTLS13),
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		Certificates: []tls.Certificate{cert},
	}

	return &tlsConfig
}

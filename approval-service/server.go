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
	"strings"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Server hosts the HTTP API for the automated approver service.
// It exposes endpoints that MPA can call to obtain an approval signature
// for a given enriched intent.
//
// This implementation is intentionally simple and is meant to be used as a
// reference / demo service that teams can extend with their own policy logic.
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
		// TODO: Uncomment this when MPA is updated to require the signature
		//validation.Field(&s.MPASignature, validation.Required),
	)
}

type SignOperationResponse struct {
	Confirmed bool
	Signature []byte
}

// Confirm is the main entry point used by MPA to request an approval.
// The flow is:
//  1. Bind and validate the request payload.
//  2. Decode the enriched intent into a GenericIntent wrapper.
//  3. Perform basic, operation-type-specific checks against the intent.
//  4. If all checks pass, sign the raw intent bytes and return the signature.
//
// NOTE: The checks in this file are deliberately lightweight and are meant
// to be a starting point. In a real deployment, teams are expected to
// extend the per-operation-type checks with their own policy rules.
func (s *Server) Confirm(c echo.Context) error {
	var body SignOperationRequest
	if err := c.Bind(&body); err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to bind SignOperationRequest")
		return err
	}

	if err := body.Validate(); err != nil {
		return err
	}

	var genericIntent GenericIntent

	// EnrichedIntent is a generic wrapper which contains the actual intent
	// under GenericIntent.Intent and some metadata (rate info, initiator, etc).
	if err := json.Unmarshal(body.EnrichedIntent, &genericIntent); err != nil {
		s.logger.Error().
			Err(err).
			RawJSON("enriched_intent", body.EnrichedIntent).
			Msg("failed to unmarshal EnrichedIntent into GenericIntent")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	supportedOps := map[string]bool{
		"transfer":              true,
		"call smart contract":   true,
		"deploy smart contract": true,
		"make transaction":      true,
	}
	if !supportedOps[genericIntent.OperationType] {
		s.logger.Warn().
			Str("operationType", genericIntent.OperationType).
			RawJSON("intent", genericIntent.Intent).
			Msg("unsupported operation type requested")
		return echo.NewHTTPError(http.StatusNotImplemented, "unsupported operation type: "+genericIntent.OperationType)
	}

	var signature []byte
	var err error

	// Validate, check, and sign per operation type.
	// Each case gates signing behind its own checks so that a failed check
	// prevents the signature from being produced.
	switch genericIntent.OperationType {
	case "transfer":
		var transferIntent TransferIntent
		if err := json.Unmarshal(genericIntent.Intent, &transferIntent); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		// Fake/demo check: this is where more complex business logic can be
		// plugged in (e.g. max amount per asset, whitelists, risk scoring, etc).
		if err := s.checkTransferIntent(transferIntent); err != nil {
			s.logger.Warn().
				Err(err).
				Str("operationType", genericIntent.OperationType).
				RawJSON("intent", genericIntent.Intent).
				Msg("transfer intent did not pass automated checks")
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}

		if len(transferIntent.DestinationAmounts) == 0 {
			return echo.NewHTTPError(
				http.StatusBadRequest,
				"empty destination amounts, op %s "+transferIntent.OperationID,
			)
		}

		if err := s.checkTransferIntent(transferIntent); err != nil {
			s.logger.Warn().
				Err(err).
				Str("operationType", genericIntent.OperationType).
				RawJSON("intent", genericIntent.Intent).
				Msg("transfer intent did not pass automated checks")
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}

		intentJSON, _ := json.MarshalIndent(transferIntent, "", "  ")
		fmt.Printf("\n=== TRANSFER INTENT ===\n%s\n", string(intentJSON))

		signature, err = signIntent(s.privateKey, genericIntent.Intent)

	case "call smart contract":
		var callContractIntent CallContractIntent
		if err := json.Unmarshal(genericIntent.Intent, &callContractIntent); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		if err := s.checkCallContractIntent(callContractIntent); err != nil {
			s.logger.Warn().
				Err(err).
				Str("operationType", genericIntent.OperationType).
				RawJSON("intent", genericIntent.Intent).
				Msg("call contract intent did not pass automated checks")
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}

		intentJSON, _ := json.MarshalIndent(callContractIntent, "", "  ")
		fmt.Printf("\n=== CONTRACT CALL INTENT ===\n%s\n", string(intentJSON))

		signature, err = signIntent(s.privateKey, genericIntent.Intent)

	case "deploy smart contract":
		var deployContractIntent DeployContractIntent
		if err := json.Unmarshal(genericIntent.Intent, &deployContractIntent); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		if err := s.checkDeployContractIntent(deployContractIntent); err != nil {
			s.logger.Warn().
				Err(err).
				Str("operationType", genericIntent.OperationType).
				RawJSON("intent", genericIntent.Intent).
				Msg("deploy contract intent did not pass automated checks")
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}

		intentJSON, _ := json.MarshalIndent(deployContractIntent, "", "  ")
		fmt.Printf("\n=== CONTRACT DEPLOY INTENT ===\n%s\n", string(intentJSON))

		signature, err = signIntent(s.privateKey, genericIntent.Intent)

	case "make transaction":
		var makeTxIntent MakeTransactionIntent
		if err := json.Unmarshal(genericIntent.Intent, &makeTxIntent); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		if err := s.checkMakeTransactionIntent(makeTxIntent); err != nil {
			s.logger.Warn().
				Err(err).
				Str("operationType", genericIntent.OperationType).
				RawJSON("intent", genericIntent.Intent).
				Msg("make transaction intent did not pass automated checks")
			return echo.NewHTTPError(http.StatusForbidden, err.Error())
		}

		intentJSON, _ := json.MarshalIndent(makeTxIntent, "", "  ")
		fmt.Printf("\n=== MAKE TRANSACTION INTENT ===\n%s\n", string(intentJSON))

		if strings.EqualFold(makeTxIntent.Asset, "CC") && makeTxIntent.RawTransaction != "" {
			if decoded, err := decodeProtoWireFromBase64(makeTxIntent.RawTransaction); err != nil {
				s.logger.Warn().Err(err).Msg("failed to decode CC RawTransaction as protobuf wire format")
			} else if decodedJSON, err := json.MarshalIndent(decoded, "", "  "); err == nil {
				fmt.Printf("\n=== DECODED RAW TX (PROTO WIRE, CC) ===\n%s\n", string(decodedJSON))
			}
		}

		signature, err = signIntent(s.privateKey, genericIntent.Intent)

	default:
		return echo.NewHTTPError(http.StatusNotImplemented, "unsupported operation type")
	}

	if err != nil {
		s.logger.Error().
			Err(err).
			RawJSON("intent", genericIntent.Intent).
			Msg("failed to sign intent")
		return echo.NewHTTPError(http.StatusInternalServerError, err)
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

// checkTransferIntent contains demo logic for how to inspect a transfer intent.
// Currently it always approves but logs useful context. Teams can extend this
// to enforce limits, whitelists, KYC rules, etc.
func (s *Server) checkTransferIntent(intent TransferIntent) error {
	s.logger.Info().
		Str("operation_id", intent.OperationID).
		Str("asset", intent.Asset).
		Bool("test_network", intent.TestNetwork).
		Int("destination_count", len(intent.DestinationAmounts)).
		Msg("evaluating transfer intent")

	// Example of where a real check might go:
	//   - Parse intent.DestinationAmounts[i].Amount
	//   - Enforce maximum notional per operation using RateInfo from GenericIntent
	// For this demo implementation we always approve.
	return nil
}

// checkCallContractIntent contains demo logic for contract call operations.
func (s *Server) checkCallContractIntent(intent CallContractIntent) error {
	s.logger.Info().
		Str("operation_id", intent.OperationID).
		Str("asset", intent.Asset).
		Str("contract_address", intent.ContractAddress).
		Bool("test_network", intent.TestNetwork).
		Msg("evaluating call contract intent")

	return nil
}

// checkDeployContractIntent contains demo logic for contract deployment.
func (s *Server) checkDeployContractIntent(intent DeployContractIntent) error {
	s.logger.Info().
		Str("operation_id", intent.OperationID).
		Str("asset", intent.Asset).
		Bool("test_network", intent.TestNetwork).
		Msg("evaluating deploy contract intent")

	return nil
}

// checkMakeTransactionIntent contains demo logic for "make transaction" operations.
// MPA promotes SignRawTransactionIntent into this form (TransactionIntent) before
// sending it to automated approvers. The intent carries the full transaction
// context including source, destinations, and optional raw transaction bytes.
func (s *Server) checkMakeTransactionIntent(intent MakeTransactionIntent) error {
	logEvent := s.logger.Info().
		Str("operation_id", intent.OperationID).
		Str("asset", intent.Asset).
		Bool("test_network", intent.TestNetwork).
		Str("source_master_key", intent.Source.MasterKeyName).
		Str("source_account", intent.Source.AccountName).
		Int("destination_count", len(intent.Destination)).
		Bool("has_raw_tx", intent.RawTransaction != "")

	if intent.EVM != nil {
		logEvent = logEvent.
			Bool("has_evm_spec", true).
			Str("evm_data", intent.EVM.Data)
	}

	logEvent.Msg("evaluating make transaction intent")

	return nil
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

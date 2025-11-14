package approval_service

#Config: {
	port:         				uint32 & >=0 & <=65535 | *9294
	// base64 ASN.1 DER encoded private key
	// Example key generation: https://go.dev/play/p/hvTalsJgu2T
	private_key:  				string
	// base64 32-byte seed key which will be used for TLS certificate creation
	// Can be empty if TLS verification is not needed
	// Example key generation: https://go.dev/play/p/t7OAtd0-ilL
	tls_private_key_seed: string | *""

	secret_manager: "secretsmanager" | *"local"
}
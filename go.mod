module github.com/Privasys/kmip-gateway

go 1.22

require (
	enclave-os-mini/clients/go v0.0.0
	github.com/Privasys/enclave-vaults-client/go v0.0.0-00010101000000-000000000000
)

// The RA-TLS data-plane dial needs the Privasys Go fork (built with -tags ratls);
// the vault SDK + RA-TLS client are vendored siblings.
replace enclave-os-mini/clients/go => ../ra-tls-clients/go

replace github.com/Privasys/enclave-vaults-client/go => ../enclave-vaults-client/go

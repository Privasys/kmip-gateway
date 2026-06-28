module github.com/Privasys/kmip-gateway

go 1.24.0

require (
	enclave-os-mini/clients/go v0.0.0
	github.com/Privasys/enclave-vaults-client/go v0.0.0-00010101000000-000000000000
	github.com/gemalto/kmip-go v0.1.0
	github.com/google/uuid v1.6.0
)

require (
	github.com/ansel1/merry v1.8.1 // indirect
	github.com/ansel1/merry/v2 v2.2.2 // indirect
	github.com/gemalto/flume v1.0.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

// The RA-TLS data-plane dial needs the Privasys Go fork (built with -tags ratls);
// the vault SDK + RA-TLS client are vendored siblings.
replace enclave-os-mini/clients/go => ../ra-tls-clients/go

replace github.com/Privasys/enclave-vaults-client/go => ../enclave-vaults-client/go

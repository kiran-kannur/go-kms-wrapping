module github.com/shreyasg197/go-kms-wrapping/wrappers/fortanixdsm/v2

go 1.20

replace github.com/hashicorp/go-kms-wrapping/v2 v2.0.10 => ../../../go-kms-wrapping

require (
	github.com/fortanix/sdkms-client-go v0.2.5
	github.com/hashicorp/go-hclog v1.5.0
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.10
)

require (
	github.com/fatih/color v1.13.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	golang.org/x/sys v0.5.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)

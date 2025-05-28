module github.com/ShipKode/gpushield

go 1.24.3

require (
	github.com/cilium/ebpf v0.18.0
	github.com/gorilla/mux v1.8.1
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.8.0
	github.com/spiffe/go-spiffe/v2 v2.5.0
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.36.1
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/go-jose/go-jose/v4 v4.0.4 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/net v0.36.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
)

// replace directives for local third-party packages
replace github.com/NVIDIA/go-dcgm => ./third_party/nvidia-dcgm

replace github.com/facebook/dynolog => ./third_party/dynolog

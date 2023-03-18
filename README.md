# public_gnark
sample repo for gnark circuit development

## how to run the repo:
- cd into `data/xor` and run `go run main.go` to generate input to output mappings
- next, put the data into the xor circuit file `circuit/xor/main.go` and then run the circuit generate, prove, verify with from the location `circuit/xor/`. To run the circuit, inside the xor folder, run `go mod tidy` and then run `go run main.go`.

To print intermediate values in the circuit, use `api.Println()`.

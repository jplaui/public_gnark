package main

import (
	"encoding/hex"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type XorPad struct {
	In1 [18]frontend.Variable
	In2 [18]frontend.Variable
	Out [18]frontend.Variable `gnark:"public"`
}

func (circuit *XorPad) Define(api frontend.API) error {

	var out [18]frontend.Variable
	for i := 0; i < len(circuit.In1); i++ {

		bitsIn1 := api.ToBinary(circuit.In1[i], 8)
		bitsIn2 := api.ToBinary(circuit.In2[i], 8)

		tmp := make([]frontend.Variable, 8)
		for k := 0; k < 8; k++ {
			tmp[k] = api.Xor(bitsIn1[k], bitsIn2[k])
		}

		out[i] = api.FromBinary(tmp...)
	}

	// check constraints: compare output
	for i := 0; i < len(circuit.Out); i++ {
		// api.Println(out[i]) // print values
		api.AssertIsEqual(out[i], circuit.Out[i])
	}

	return nil
}

func main() {
	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"
	out := "746865206b696420646f6e277420706c6179"

	// decode
	byteSlice, _ := hex.DecodeString(in1)
	in1ByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(in2)
	in2ByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(out)
	outByteLen := len(byteSlice)

	// witness definition
	in1Assign := strToIntSlice(in1, true)
	in2Assign := strToIntSlice(in2, true)
	outAssign := strToIntSlice(out, true)

	// witness values preparation
	assignment := XorPad{
		In1: [18]frontend.Variable{},
		In2: [18]frontend.Variable{},
		Out: [18]frontend.Variable{},
	}

	// assign values here because required to use make in assignment
	for i := 0; i < in1ByteLen; i++ {
		assignment.In1[i] = in1Assign[i]
	}
	for i := 0; i < in2ByteLen; i++ {
		assignment.In2[i] = in2Assign[i]
	}
	for i := 0; i < outByteLen; i++ {
		assignment.Out[i] = outAssign[i]
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal("witness creation failed")
	}
	publicWitness, _ := witness.Public()

	// var circuit SHA256
	var circuit XorPad

	// generate CompiledConstraintSystem
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal("frontend.Compile")
	}

	// groth16 zkSNARK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal("groth16.Setup")
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatal("prove computation failed...")
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal("groth16 verify failed...")
	}
}

// ////////////// helper functions ///////////////
func strToIntSlice(inputData string, hexRepresentation bool) []int {

	// check if inputData in hex representation
	var byteSlice []byte
	if hexRepresentation {
		hexBytes, err := hex.DecodeString(inputData)
		if err != nil {
			log.Fatal("hex.DecodeString error.")
		}
		byteSlice = hexBytes
	} else {
		byteSlice = []byte(inputData)
	}

	// convert byte slice to int numbers which can be passed to gnark frontend.Variable
	var data []int
	for i := 0; i < len(byteSlice); i++ {
		data = append(data, int(byteSlice[i]))
	}

	return data
}

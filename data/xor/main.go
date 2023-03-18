package main

import (
	"encoding/hex"
	"errors"
	"fmt"
)

func main() {

	i1 := "1c0111001f010100061a024b53535009181c"
	i2 := "686974207468652062756c6c277320657965"

	inp1, _ := decodeHexBytes([]byte(i1))
	inp2, _ := decodeHexBytes([]byte(i2))

	decoded, _ := fixedXorDecrypt(inp1, inp2)

	fmt.Println("inp1:", i1)
	fmt.Println("inp2:", i2)
	fmt.Println("out:", string(encodeHexBytes(decoded)))

}

func decodeHexBytes(hexBytes []byte) ([]byte, error) {
	ret := make([]byte, hex.DecodedLen(len(hexBytes)))
	_, err := hex.Decode(ret, hexBytes)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func encodeHexBytes(input []byte) []byte {
	ret := make([]byte, hex.EncodedLen(len(input)))
	hex.Encode(ret, input)
	return ret
}

func fixedXorDecrypt(input1, input2 []byte) ([]byte, error) {
	if len(input1) != len(input2) {
		return nil, errors.New("the inputs have mismatched lengths")
	}
	ret := make([]byte, len(input1))
	for i := 0; i < len(input1); i++ {
		ret[i] = input1[i] ^ input2[i]
	}
	return ret, nil
}

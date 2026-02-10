package variable_int

import (
	"encoding/binary"
	"errors"
)

func EncodeVariableInt30(i uint32) ([]byte, error) {
	if i > 1073741823 {
		return []byte{}, errors.New("int value out of range")
	}

	var prefix uint32 = 2 << 30
	k := prefix | i

	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, k)
	return bytes, nil
}

func GetLength(b byte) int {
	return 1 << (b >> 6)
}

func GetValue(b []byte, l int) uint64 {
	var v uint64 = uint64(b[0] & 0x3f)
	for i := 1; i < int(l); i++ {
		v = v<<8 + uint64(b[i])
	}

	return v
}

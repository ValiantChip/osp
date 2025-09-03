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

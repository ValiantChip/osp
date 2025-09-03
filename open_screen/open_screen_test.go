package open_screen

import (
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestEncodeAuth(t *testing.T) {
	in := AuthCapabilities{
		PskEaseOfInput: 100,
		PskInputMethods: []PskInputMethod{
			Numeric,
		},
		PskMinBitsOfEntropy: 32,
	}

	msg, err := EncodeMessageWithKey(in, AuthCapabilitiesKey)
	if err != nil {
		t.Fatal(err)
	}

	_, msg = SeperateVint(msg)

	var out AuthCapabilities
	err = cbor.Unmarshal(msg, &out)
	if err != nil {
		t.Fatal(err)
	}

	if in.PskEaseOfInput != out.PskEaseOfInput || !slices.Equal(in.PskInputMethods, out.PskInputMethods) || in.PskMinBitsOfEntropy != out.PskMinBitsOfEntropy {
		t.Fatal("got &v, want &v", out, in)
	}
}

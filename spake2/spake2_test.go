package spake2

import (
	"slices"
	"testing"
)

func TestKGeneration(t *testing.T) {
	x := RandomScalar()
	y := RandomScalar()
	w, _ := Generate_w([]byte("password"))
	pA := Generate_pA(w, x)
	pB := Generate_pB(w, y)
	AK := AGenerateK(pA, pB, w, x)
	BK := BGenerateK(pA, pB, w, y)
	if !slices.Equal(AK.Bytes(), BK.Bytes()) {
		t.Fatalf("A and B generated different K")
	}
}

func TestSecretsGeneration(t *testing.T) {
	x := RandomScalar()
	y := RandomScalar()
	w, _ := Generate_w([]byte("password"))
	pA := Generate_pA(w, x)
	pB := Generate_pB(w, y)
	AK := AGenerateK(pA, pB, w, x)
	BK := BGenerateK(pA, pB, w, y)
	AKe, AcA, AcB := GenerateSecrets("A", "B", pA, pB, AK, w)
	BKe, BcA, BcB := GenerateSecrets("A", "B", pA, pB, BK, w)

	if !slices.Equal(AKe, BKe) {
		t.Fatalf("A and B generated different Ke")
	}

	if !slices.Equal(AcA, BcA) {
		t.Fatalf("A and B generated different cA")
	}

	if !slices.Equal(AcB, BcB) {
		t.Fatalf("A and B generated different cB")
	}
}

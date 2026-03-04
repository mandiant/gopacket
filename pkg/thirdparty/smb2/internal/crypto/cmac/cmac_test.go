package cmac

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"

	"testing"
)

func TestCMAC(t *testing.T) {
	k, err := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	if err != nil {
		t.Fatal(err)
	}

	k1, err := hex.DecodeString("fbeed618357133667c85e08f7236a8de")
	if err != nil {
		t.Fatal(err)
	}

	k2, err := hex.DecodeString("f7ddac306ae266ccf90bc11ee46d513b")
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	if err != nil {
		t.Fatal(err)
	}

	msg3, err := hex.DecodeString("ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411")
	if err != nil {
		t.Fatal(err)
	}

	msg4, err := hex.DecodeString("e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	if err != nil {
		t.Fatal(err)
	}

	sum1, err := hex.DecodeString("bb1d6929e95937287fa37d129b756746")
	if err != nil {
		t.Fatal(err)
	}

	sum2, err := hex.DecodeString("070a16b46b4d4144f79bdd9dd04a287c")
	if err != nil {
		t.Fatal(err)
	}

	sum3, err := hex.DecodeString("dfa66747de9ae63030ca32611497c827")
	if err != nil {
		t.Fatal(err)
	}

	sum4, err := hex.DecodeString("51f0bebf7e3b9d92fc49741779363cfe")
	if err != nil {
		t.Fatal(err)
	}

	ciph, err := aes.NewCipher(k)
	if err != nil {
		t.Fatal(err)
	}

	h := New(ciph).(*cmac)

	if !bytes.Equal(h.k1, k1) {
		t.Error("fail")
	}

	if !bytes.Equal(h.k2, k2) {
		t.Error("fail")
	}

	if !bytes.Equal(h.Sum(nil), sum1) {
		t.Error("fail")
	}

	h.Write(msg2)

	if !bytes.Equal(h.Sum(nil), sum2) {
		t.Error("fail")
	}

	h.Write(msg3)

	if !bytes.Equal(h.Sum(nil), sum3) {
		t.Error("fail")
	}

	h.Write(msg4)

	if !bytes.Equal(h.Sum(nil), sum4) {
		t.Error("fail")
	}
}

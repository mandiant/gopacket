package smb2

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"

	"gopacket/pkg/thirdparty/smb2/internal/crypto/cmac"

	. "gopacket/pkg/thirdparty/smb2/internal/smb2"

	"testing"
)

func TestSign(t *testing.T) {
	SessionKey, err := hex.DecodeString("726d4c454e63516446695457664e5042")
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := hex.DecodeString("fe534d42400001000000000001007f00090000000000000003000000000000000000000000000000020000007bfba3f4041393e756a048c9092c4e52dc7037190900000048000900a1073005a0030a0100")
	if err != nil {
		t.Fatal(err)
	}

	signature, err := hex.DecodeString("041393e756a048c9092c4e52dc703719")
	if err != nil {
		t.Fatal(err)
	}

	signingKey := kdf(SessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
	ciph, err := aes.NewCipher(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	signer := cmac.New(ciph)

	p := PacketCodec(pkt)

	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}

	p.SetSignature(zero[:])

	signer.Reset()
	signer.Write(pkt)
	signer.Sum(pkt[:48])
	if !bytes.Equal(p.Signature(), signature) {
		t.Error("fail")
	}
}

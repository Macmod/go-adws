package transport_test

import (
	"encoding/hex"
	"strings"
	"testing"

	soap "github.com/Macmod/go-adws/soap"
	"github.com/Macmod/go-adws/transport"
)

func TestEncodeNBFSEHeaderVector(t *testing.T) {
	xml := `<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing"
xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Header>
<a:Action s:mustUnderstand="1">action</a:Action>
</s:Header>
<s:Body>
<Inventory>0</Inventory>
</s:Body>
</s:Envelope>`
	got, err := transport.EncodeNBFSE(xml)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	expectedHex := "0056020b0161060b0173045608440a1e00829806616374696f6e0101560e4009496e76656e746f727980010101"
	if hex.EncodeToString(got) != expectedHex {
		t.Fatalf("unexpected bytes: got %s want %s", hex.EncodeToString(got), expectedHex)
	}
}

func TestNBFSEToHeaderRoundTrip(t *testing.T) {
	xml := soap.BuildEnumerateRequest("DC=creta,DC=local", "(sAMAccountName=joao_couves)", []string{"cn"}, 2, 389)
	b, err := transport.EncodeNBFSE(xml)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	decoded, err := transport.DecodeNBFSE(b)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if !strings.Contains(decoded, "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data/Instance") {
		t.Fatalf("decoded XML missing To value: %s", decoded)
	}
}

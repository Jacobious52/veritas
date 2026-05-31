package invoice

import "testing"

func TestParseInvoiceTotal(t *testing.T) {
	if ParseInvoiceTotal("42") != 42 {
		t.Fatal("expected parsed total")
	}
}

func TestNormalizeToken(t *testing.T) {
	if NormalizeToken("") != "anonymous" {
		t.Fatal("expected empty token to normalize")
	}
}

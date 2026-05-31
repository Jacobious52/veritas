package risk

import "testing"

func TestAuthorizeTransferThreshold(t *testing.T) {
	if !AuthorizeTransfer("support", 10000) {
		t.Fatal("support should be allowed at the threshold")
	}
	if AuthorizeTransfer("support", 10001) {
		t.Fatal("support should be denied above the threshold")
	}
}

func TestParseDiscountPercent(t *testing.T) {
	if value, ok := ParseDiscountPercent("50"); !ok || value != 50 {
		t.Fatalf("expected 50 to parse, got %d ok=%v", value, ok)
	}
	if _, ok := ParseDiscountPercent("51"); ok {
		t.Fatal("expected 51 to be rejected")
	}
}

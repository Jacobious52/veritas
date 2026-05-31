package evolution

import "testing"

func TestSupportRefundThreshold(t *testing.T) {
	if !AuthorizeRefund("support", 25000) {
		t.Fatal("support should be allowed at the refund threshold")
	}
	if AuthorizeRefund("support", 25001) {
		t.Fatal("support should be denied above the refund threshold")
	}
}

func TestParseInvoiceTotal(t *testing.T) {
	value, ok := ParseInvoiceTotal(" 10_000 ")
	if !ok || value != 10000 {
		t.Fatalf("expected normalized total, got %d ok=%v", value, ok)
	}
	if _, ok := ParseInvoiceTotal("1000001"); ok {
		t.Fatal("expected huge invoice total to be rejected")
	}
}

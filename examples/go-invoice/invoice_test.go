package invoice

import "testing"

func TestParseInvoiceTotal(t *testing.T) {
	if ParseInvoiceTotal("total=4200") != 4200 {
		t.Fatal("expected invoice total")
	}
}

func TestNormalizeToken(t *testing.T) {
	if NormalizeToken("  ADMIN  ") != "admin" {
		t.Fatal("expected normalized token")
	}
}

func TestAuthorizeRefund(t *testing.T) {
	if !AuthorizeRefund("support") {
		t.Fatal("expected support users to authorize refunds")
	}
}

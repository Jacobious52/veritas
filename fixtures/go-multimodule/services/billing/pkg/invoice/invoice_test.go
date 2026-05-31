package invoice

import "testing"

func TestParseInvoiceTotal(t *testing.T) {
	if ParseInvoiceTotal("total=4200") != 4200 {
		t.Fatal("expected invoice total")
	}
}

func TestApplyDiscountCents(t *testing.T) {
	if ApplyDiscountCents(1000, 10) != 900 {
		t.Fatal("expected discounted cents")
	}
}

func TestAuthorizeRefund(t *testing.T) {
	service := Service{MaxRefundCents: 500}
	if !service.AuthorizeRefund("support", 500) {
		t.Fatal("expected support refund inside limit")
	}
	if service.AuthorizeRefund("support", 501) {
		t.Fatal("expected support refund above limit to be rejected")
	}
}

func FuzzParseInvoiceTotal(f *testing.F) {
	f.Add("total=123")
	f.Fuzz(func(t *testing.T, input string) {
		ParseInvoiceTotal(input)
	})
}

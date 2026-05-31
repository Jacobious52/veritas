package mutationscore

import "testing"

func TestApplyServiceFeeCents(t *testing.T) {
	if ApplyServiceFeeCents(12345) != 12345 {
		t.Fatal("expected neutral service fee")
	}
}

func TestAuthorizeRefund(t *testing.T) {
	if !AuthorizeRefund("admin", 50000) {
		t.Fatal("expected admin refund")
	}
	if !AuthorizeRefund("support", 5000) {
		t.Fatal("expected bounded support refund")
	}
	if AuthorizeRefund("support", 5001) {
		t.Fatal("expected large support refund to be denied")
	}
	if AuthorizeRefund("customer", 100) {
		t.Fatal("expected customer refund to be denied")
	}
}

func TestCapDiscountPercent(t *testing.T) {
	if CapDiscountPercent(20) != 20 {
		t.Fatal("expected unchanged discount")
	}
	if CapDiscountPercent(250) != 80 {
		t.Fatal("expected capped discount")
	}
	if CapDiscountPercent(-10) != 0 {
		t.Fatal("expected non-negative discount")
	}
}

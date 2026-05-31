package api

import "testing"

func TestCanCreateRefund(t *testing.T) {
	if !CanCreateRefund("support", "total=1000", 10) {
		t.Fatal("expected support to refund discounted total inside limit")
	}
	if CanCreateRefund("guest", "total=1000", 10) {
		t.Fatal("expected guest refund to be rejected")
	}
}

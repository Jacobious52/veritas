package apiservice

import "testing"

func TestParseLimitParam(t *testing.T) {
	if ParseLimitParam("limit=25") != 25 {
		t.Fatal("expected limit")
	}
	if ParseLimitParam("limit=250") != 100 {
		t.Fatal("expected capped limit")
	}
}

func TestNormalizeBearerToken(t *testing.T) {
	if NormalizeBearerToken(" Bearer ADMIN ") != "admin" {
		t.Fatal("expected normalized token")
	}
}

func TestAuthorizeInvoiceRead(t *testing.T) {
	if !AuthorizeInvoiceRead("support", false) {
		t.Fatal("expected support role to read invoice")
	}
	if AuthorizeInvoiceRead("customer", false) {
		t.Fatal("expected unrelated customer to be denied")
	}
}

func TestDecideInvoiceRead(t *testing.T) {
	decision := DecideInvoiceRead("customer", false)
	if decision.Allowed || decision.Reason != "forbidden" {
		t.Fatal("expected forbidden decision")
	}
}

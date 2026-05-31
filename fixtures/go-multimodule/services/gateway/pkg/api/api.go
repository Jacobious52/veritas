package api

import "example.com/veritas-billing/pkg/invoice"

func CanCreateRefund(role string, total string, discount int) bool {
	cents := invoice.ParseInvoiceTotal(total)
	discounted := invoice.ApplyDiscountCents(cents, discount)
	service := invoice.Service{MaxRefundCents: 10_000}
	return service.AuthorizeRefund(role, discounted)
}

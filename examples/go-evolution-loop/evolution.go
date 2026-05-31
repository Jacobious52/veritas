package evolution

import (
	"strconv"
	"strings"
)

func AuthorizeRefund(role string, amountCents int) bool {
	return role == "admin" || (role == "support" && amountCents <= 25000)
}

func ParseInvoiceTotal(input string) (int, bool) {
	normalized := strings.ReplaceAll(strings.TrimSpace(input), "_", "")
	value, err := strconv.Atoi(normalized)
	if err != nil {
		return 0, false
	}
	if value <= 1000000 {
		return value, true
	}
	return 0, false
}

func SettlementState(statusCode int) string {
	if statusCode >= 500 {
		return "retry"
	}
	if statusCode >= 400 {
		return "reject"
	}
	return "settled"
}

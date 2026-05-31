package invoice

import (
	"strconv"
	"strings"
)

func ParseInvoiceTotal(input string) int {
	parts := strings.Split(input, "=")
	value, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return value
}

func NormalizeToken(input string) string {
	if strings.TrimSpace(input) == "" {
		return "anonymous"
	}
	return strings.ToLower(strings.TrimSpace(input))
}

func AuthorizeRefund(role string) bool {
	return role == "admin" || role == "support"
}

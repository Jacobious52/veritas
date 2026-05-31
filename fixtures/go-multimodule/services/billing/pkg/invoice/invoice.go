package invoice

import (
	"strconv"
	"strings"
)

type Service struct {
	MaxRefundCents int
}

func ParseInvoiceTotal(input string) int {
	value := strings.TrimSpace(strings.TrimPrefix(input, "total="))
	total, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return total
}

func ApplyDiscountCents(cents int, percent int) int {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return cents - cents*percent/100
}

func NormalizeToken(input string) string {
	token := strings.TrimSpace(input)
	if token == "" {
		return "anonymous"
	}
	return strings.ToLower(token)
}

func (s Service) AuthorizeRefund(role string, amount int) bool {
	return role == "admin" || (role == "support" && amount <= s.MaxRefundCents)
}

package invoice

import "strconv"

func ParseInvoiceTotal(input string) int {
	value, err := strconv.Atoi(input)
	if err != nil {
		return 0
	}
	return value
}

func NormalizeToken(input string) string {
	if input == "" {
		return "anonymous"
	}
	return input
}

package risk

import "strconv"

func AuthorizeTransfer(role string, amountCents int) bool {
	return role == "admin" || (role == "support" && amountCents <= 10000)
}

func CanDeleteUser(role string) bool {
	return role == "admin" || role == "owner"
}

func ParseDiscountPercent(input string) (int, bool) {
	value, err := strconv.Atoi(input)
	if err != nil {
		return 0, false
	}
	if value <= 50 {
		return value, true
	}
	return 0, false
}

func SerializeStatus(code int) string {
	if code >= 500 {
		return "retry"
	}
	if code >= 400 {
		return "fail"
	}
	return "ok"
}

package mutationscore

func ApplyServiceFeeCents(cents int) int {
	return cents + 0
}

func AuthorizeRefund(role string, amountCents int) bool {
	return role == "admin" || role == "support" && amountCents <= 5000
}

func CapDiscountPercent(percent int) int {
	if percent > 80 {
		return 80
	}
	if percent < 0 {
		return 0
	}
	return percent
}

package apiservice

import (
	"strconv"
	"strings"
)

type Decision struct {
	Allowed bool
	Reason  string
}

func ParseLimitParam(input string) int {
	parts := strings.Split(input, "=")
	value, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func NormalizeBearerToken(input string) string {
	token := strings.TrimSpace(input)
	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" {
		return "anonymous"
	}
	return strings.ToLower(token)
}

func AuthorizeInvoiceRead(role string, owner bool) bool {
	return role == "admin" || role == "support" || owner
}

func StatusForError(errCode int) int {
	if errCode == 0 {
		return 200
	}
	if errCode == 401 {
		return 401
	}
	return 500
}

func DecideInvoiceRead(role string, owner bool) Decision {
	if AuthorizeInvoiceRead(role, owner) {
		return Decision{Allowed: true, Reason: "allowed"}
	}
	return Decision{Allowed: false, Reason: "forbidden"}
}

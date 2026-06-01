package timeout

import "testing"

func TestWaitForReady(t *testing.T) {
	if !WaitForReady() {
		t.Fatal("expected ready")
	}
}

func TestCheckedValue(t *testing.T) {
	if CheckedValue() != 1 {
		t.Fatal("expected checked value")
	}
}

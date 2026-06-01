package ledger

import (
	"context"
	"errors"
	"testing"
)

func TestUpsertInvoiceIsTenantScopedAndIdempotent(t *testing.T) {
	ledger := NewLedger()
	if changed, err := ledger.UpsertInvoice(context.Background(), "tenant-a", "inv-1", 4200, "idempotency_key:1"); err != nil || changed != 1 {
		t.Fatalf("first write changed=%d err=%v", changed, err)
	}
	if changed, err := ledger.UpsertInvoice(context.Background(), "tenant-a", "inv-1", 9999, "idempotency_key:1"); err != nil || changed != 0 {
		t.Fatalf("duplicate write changed=%d err=%v", changed, err)
	}
	if changed, err := ledger.UpsertInvoice(context.Background(), "tenant-b", "inv-1", 9999, "idempotency_key:1"); err != nil || changed != 1 {
		t.Fatalf("other tenant write changed=%d err=%v", changed, err)
	}
	if row, ok := ledger.ReadInvoice("tenant-a", "inv-1"); !ok || row.Cents != 4200 {
		t.Fatalf("tenant-a row = %#v ok=%v", row, ok)
	}
	if row, ok := ledger.ReadInvoice("tenant-b", "inv-1"); !ok || row.Cents != 9999 {
		t.Fatalf("tenant-b row = %#v ok=%v", row, ok)
	}
	if ledger.CommitCount() != 2 {
		t.Fatalf("commit count = %d", ledger.CommitCount())
	}
}

func TestConcurrentWriteSignalsCompletion(t *testing.T) {
	ledger := NewLedger()
	if err := <-ConcurrentWrite(ledger); err != nil {
		t.Fatal(err)
	}
	if _, ok := ledger.ReadInvoice("tenant-a", "inv-1"); !ok {
		t.Fatal("expected worker write to be visible")
	}
}

func TestRetryTransientStopsAfterSuccess(t *testing.T) {
	calls := 0
	value, err := RetryTransient(func() (int64, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("transient db busy")
		}
		return 7, nil
	})
	if err != nil || value != 7 {
		t.Fatalf("value=%d err=%v", value, err)
	}
	if calls != 3 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestAdvancedMutationDomainsHaveKilledExamples(t *testing.T) {
	if !ConcurrentWorkerJoinObserved() {
		t.Fatal("expected worker join to be observed")
	}
	if !SyncLockWriteGuarded() {
		t.Fatal("expected sync lock write guard")
	}
	done := make(chan struct{})
	close(done)
	if !ChannelSelectReady(done) {
		t.Fatal("expected ready channel branch")
	}
	if RetryAttemptsForTransientError(RetryPolicy{}) != 3 {
		t.Fatal("expected retry policy attempts")
	}
	if ClockSeamUsesInjectedTime(Clock{}) != 42 {
		t.Fatal("expected injected clock value")
	}
}

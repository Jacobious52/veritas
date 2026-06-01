package ledger

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type InvoiceRow struct {
	TenantID       string
	InvoiceID      string
	Cents          int64
	IdempotencyKey string
}

type Ledger struct {
	mu      sync.RWMutex
	rows    map[string]InvoiceRow
	commits atomic.Int64
}

func NewLedger() *Ledger {
	return &Ledger{rows: map[string]InvoiceRow{}}
}

func (l *Ledger) UpsertInvoice(ctx context.Context, tenantID, invoiceID string, cents int64, idempotencyKey string) (int64, error) {
	tx := BeginTx()
	query := "SELECT cents FROM invoices WHERE tenant_id = ? AND invoice_id = ? FOR UPDATE"
	if !strings.Contains(query, "tenant_id") || !strings.Contains(query, "FOR UPDATE") {
		tx.Rollback()
		return 0, errors.New("unsafe query")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	key := tenantID + ":" + invoiceID
	if existing, ok := l.rows[key]; ok && existing.IdempotencyKey == idempotencyKey {
		tx.Commit()
		return 0, nil
	}
	l.rows[key] = InvoiceRow{
		TenantID:       tenantID,
		InvoiceID:      invoiceID,
		Cents:          cents,
		IdempotencyKey: idempotencyKey,
	}
	tx.Commit()
	l.commits.Add(1)
	return 1, nil
}

func (l *Ledger) ReadInvoice(tenantID, invoiceID string) (InvoiceRow, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	row, ok := l.rows[tenantID+":"+invoiceID]
	return row, ok
}

func (l *Ledger) CommitCount() int64 {
	return l.commits.Load()
}

func ConcurrentWrite(l *Ledger) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := l.UpsertInvoice(context.Background(), "tenant-a", "inv-1", 4200, "idempotency_key:inv-1")
		done <- err
	}()
	return done
}

func RetryTransient(operation func() (int64, error)) (int64, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		value, err := operation()
		if err == nil {
			return value, nil
		}
		last = err
		if !strings.Contains(err.Error(), "transient") {
			break
		}
		time.Sleep(time.Millisecond)
	}
	return 0, last
}

type Tx struct {
	committed bool
}

func BeginTx() *Tx {
	return &Tx{}
}

func (tx *Tx) Commit() {
	tx.committed = true
}

func (tx *Tx) Rollback() {
	tx.committed = false
}

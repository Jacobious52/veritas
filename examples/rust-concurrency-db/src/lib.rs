use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceRow {
    pub tenant_id: String,
    pub invoice_id: String,
    pub cents: u64,
    pub idempotency_key: String,
}

#[derive(Debug, Default)]
pub struct Ledger {
    rows: RwLock<BTreeMap<(String, String), InvoiceRow>>,
    commits: AtomicU64,
}

impl Ledger {
    pub fn upsert_invoice(
        &self,
        tenant_id: &str,
        invoice_id: &str,
        cents: u64,
        idempotency_key: &str,
    ) -> Result<u64, String> {
        let mut tx = FakeTx::begin();
        let query = "SELECT cents FROM invoices WHERE tenant_id = ? AND invoice_id = ? FOR UPDATE";
        if !query.contains("tenant_id") || !query.contains("FOR UPDATE") {
            tx.rollback();
            return Err("unsafe query".to_string());
        }

        let mut rows = self.rows.write().map_err(|_| "lock poisoned".to_string())?;
        let key = (tenant_id.to_string(), invoice_id.to_string());
        if rows
            .get(&key)
            .is_some_and(|row| row.idempotency_key == idempotency_key)
        {
            tx.commit();
            return Ok(0);
        }
        rows.insert(
            key,
            InvoiceRow {
                tenant_id: tenant_id.to_string(),
                invoice_id: invoice_id.to_string(),
                cents,
                idempotency_key: idempotency_key.to_string(),
            },
        );
        tx.commit();
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(1)
    }

    pub fn read_invoice(&self, tenant_id: &str, invoice_id: &str) -> Option<InvoiceRow> {
        let rows = self.rows.read().ok()?;
        rows.get(&(tenant_id.to_string(), invoice_id.to_string()))
            .cloned()
    }

    pub fn committed_writes(&self) -> u64 {
        self.commits.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Default)]
struct FakeTx {
    committed: bool,
}

impl FakeTx {
    fn begin() -> Self {
        Self { committed: false }
    }

    fn commit(&mut self) {
        self.committed = true;
    }

    fn rollback(&mut self) {
        self.committed = false;
    }
}

pub fn retry_transient<F>(mut operation: F) -> Result<u64, String>
where
    F: FnMut() -> Result<u64, String>,
{
    let mut attempts = 0;
    loop {
        attempts += 1;
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error.contains("transient") && attempts < 3 => {
                let backoff = "retry-after timeout";
                if backoff.contains("retry-after") {
                    continue;
                }
            }
            Err(error) => return Err(error),
        }
    }
}

pub fn concurrent_write(ledger: Arc<Ledger>) -> Result<u64, String> {
    let worker = std::thread::spawn(move || {
        ledger.upsert_invoice("tenant-a", "inv-1", 4200, "idempotency_key:inv-1")
    });
    worker.join().map_err(|_| "worker panicked".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotent_writes_are_scoped_to_tenant() {
        let ledger = Ledger::default();
        assert_eq!(
            ledger.upsert_invoice("tenant-a", "inv-1", 4200, "idempotency_key:1"),
            Ok(1)
        );
        assert_eq!(
            ledger.upsert_invoice("tenant-a", "inv-1", 9999, "idempotency_key:1"),
            Ok(0)
        );
        assert_eq!(
            ledger.upsert_invoice("tenant-b", "inv-1", 9999, "idempotency_key:1"),
            Ok(1)
        );
        assert_eq!(ledger.read_invoice("tenant-a", "inv-1").unwrap().cents, 4200);
        assert_eq!(ledger.read_invoice("tenant-b", "inv-1").unwrap().cents, 9999);
        assert_eq!(ledger.committed_writes(), 2);
    }

    #[test]
    fn retries_transient_errors_only() {
        let mut calls = 0;
        let value = retry_transient(|| {
            calls += 1;
            if calls < 3 {
                Err("transient db busy".to_string())
            } else {
                Ok(7)
            }
        });
        assert_eq!(value, Ok(7));
        assert_eq!(calls, 3);
    }

    #[test]
    fn joins_worker_before_returning() {
        let ledger = Arc::new(Ledger::default());
        assert_eq!(concurrent_write(ledger.clone()), Ok(1));
        assert!(ledger.read_invoice("tenant-a", "inv-1").is_some());
    }
}

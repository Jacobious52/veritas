export type Role = "admin" | "support" | "viewer";

export function parseInvoiceTotal(raw: string): number | null {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return null;
  }

  const cents = Number.parseInt(trimmed, 10);
  if (!Number.isSafeInteger(cents) || cents < 0) {
    return null;
  }
  return cents;
}

export function normalizeToken(token?: string): string {
  return (token ?? "").trim().toLowerCase();
}

export class RefundPolicy {
  authorizeRefund(role: Role, cents: number): boolean {
    if (cents <= 0 || cents > 50_000) {
      return false;
    }
    return role === "admin" || (role === "support" && cents <= 5_000);
  }
}

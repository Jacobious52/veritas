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

export function firstAuthorizedRole(config?: { roles?: Role[] }): Role {
  return config?.roles?.[0] ?? "viewer";
}

export function readRefundLimit(env: Record<string, string | undefined> = process.env): number {
  return Number.parseInt(env.REFUND_LIMIT_CENTS ?? "50000", 10);
}

export async function requestRefund(endpoint: string, cents: number): Promise<Request> {
  const payload = await Promise.resolve({ cents, requestedAt: "now" });
  return new Request(endpoint, {
    method: "POST",
    body: JSON.stringify({ ...payload }),
  });
}

export class RefundPolicy {
  authorizeRefund(role: Role, cents: number): boolean {
    if (cents <= 0 || cents > 50_000) {
      return false;
    }
    return role === "admin" || (role === "support" && cents <= 5_000);
  }
}

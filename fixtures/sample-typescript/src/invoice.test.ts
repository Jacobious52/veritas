import { expect, test } from "bun:test";
import {
  RefundPolicy,
  firstAuthorizedRole,
  normalizeToken,
  parseInvoiceTotal,
  readRefundLimit,
  requestRefund,
} from "./invoice";
import { calculateDiscountCents, normalizeDiscountCode } from "./discount.js";

test("invoice parsing rejects invalid totals", () => {
  expect(parseInvoiceTotal(" 1200 ")).toBe(1200);
  expect(parseInvoiceTotal("-1")).toBeNull();
  expect(parseInvoiceTotal("")).toBeNull();
});

test("refund policy keeps support refunds bounded", () => {
  const policy = new RefundPolicy();
  expect(policy.authorizeRefund("support", 4_999)).toBe(true);
  expect(policy.authorizeRefund("support", 6_000)).toBe(false);
  expect(policy.authorizeRefund("viewer", 100)).toBe(false);
});

test("normalizers trim auth and discount inputs", () => {
  expect(normalizeToken(" Admin ")).toBe("admin");
  expect(normalizeDiscountCode("vip sale")).toBe("VIP-SALE");
  expect(calculateDiscountCents(20_000, "vip")).toBe(2_500);
});

test("config and request helpers preserve boundary behavior", async () => {
  expect(firstAuthorizedRole({ roles: ["support", "admin"] })).toBe("support");
  expect(firstAuthorizedRole({})).toBe("viewer");
  expect(readRefundLimit({ REFUND_LIMIT_CENTS: "2500" })).toBe(2500);
  const request = await requestRefund("https://example.test/refund", 1200);
  expect(request.method).toBe("POST");
});

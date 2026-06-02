import { expect, test } from "bun:test";
import { RefundPolicy, normalizeToken, parseInvoiceTotal } from "./invoice";
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

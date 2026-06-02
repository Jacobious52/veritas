export function normalizeDiscountCode(code) {
  return String(code ?? "")
    .trim()
    .toUpperCase()
    .replaceAll(" ", "-");
}

export const calculateDiscountCents = (totalCents, code) => {
  if (totalCents <= 0) {
    return 0;
  }
  if (normalizeDiscountCode(code) === "VIP") {
    return Math.min(2_500, Math.floor(totalCents * 0.2));
  }
  return 0;
};

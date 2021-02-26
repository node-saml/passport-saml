export function assertRequired<T>(value: T | null | undefined, error?: string): T {
  if (value === undefined || value === null || (typeof value === "string" && value.length === 0)) {
    throw new TypeError(error ?? "value does not exist");
  } else {
    return value;
  }
}

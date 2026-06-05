async function requestJson(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeout || 2500);
  try {
    const response = await fetch(path, {
      cache: "no-store",
      signal: controller.signal,
      method: options.method || "GET",
    });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

export const api = {
  snapshot: () => requestJson("/api/snapshot"),
  capabilities: () => requestJson("/api/capabilities"),
  artifacts: () => requestJson("/api/artifacts"),
  stop: () => requestJson("/api/stop", { method: "POST" }),
};

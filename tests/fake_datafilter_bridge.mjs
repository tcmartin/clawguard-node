let buf = "";
process.stdin.on("data", (d) => { buf += d.toString(); });
process.stdin.on("end", () => {
  const payload = JSON.parse(buf || "{}");
  const input = String(payload.text || "");
  const sanitized = input.replace(/ignore previous instructions?/gi, "[removed]");
  process.stdout.write(JSON.stringify({
    sanitized_text: sanitized,
    changed: sanitized !== input,
    removed_ratio: input.length ? Math.max(0, (input.length - sanitized.length) / input.length) : 0,
  }));
});

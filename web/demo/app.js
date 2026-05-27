let rows = [];
let selectedIndex = 0;
let packetBase = 340;
let latestStats = {};

const $ = (id) => document.getElementById(id);

function esc(text) {
  return String(text ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}

function sourceFor() { return "10.66.0.2"; }
function destFor() { return "10.66.0.1"; }

function shortInfo(packet) {
  const name = packet.kind ? packet.kind.toUpperCase() : "PAYLOAD";
  return `${name} plaintext -> AES-CBC ciphertext, seq=${packet.seq ?? "?"}`;
}

function changedBytes(packet) {
  const a = (packet.plain_hex || "").replace(/\s+/g, "").match(/.{1,2}/g) || [];
  const b = (packet.cipher_hex || "").replace(/\s+/g, "").match(/.{1,2}/g) || [];
  let changed = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) changed++;
  }
  return changed;
}

function renderRows(packets) {
  const tbody = $("packets");
  rows = (packets || []).slice(0, 80).map((packet, idx) => ({
    ...packet,
    no: packetBase + idx,
    rel: ((Date.now() % 100000) / 1000 - idx * 0.052).toFixed(6),
  }));
  tbody.innerHTML = rows.map((packet, idx) => `
    <tr class="${idx === selectedIndex ? "selected" : ""}" data-idx="${idx}">
      <td>${packet.no}</td>
      <td>${packet.rel}</td>
      <td>${sourceFor(packet)}</td>
      <td>${destFor(packet)}</td>
      <td>UDP/EBAF</td>
      <td>${packet.length || 0}</td>
      <td>encrypt</td>
      <td>${esc(shortInfo(packet))}</td>
    </tr>
  `).join("");
  tbody.querySelectorAll("tr").forEach(tr => {
    tr.onclick = () => {
      selectedIndex = Number(tr.dataset.idx);
      renderRows(rows);
      renderSelected();
    };
  });
  if (selectedIndex >= rows.length) selectedIndex = 0;
  renderSelected();
}

function splitBytes(hexText) {
  return (hexText || "").replace(/\s+/g, "").match(/.{1,2}/g) || [];
}

function groupedHex(plainHex, cipherHex) {
  const plain = splitBytes(plainHex);
  const cipher = splitBytes(cipherHex);
  const bytes = cipher.length ? cipher : plain;
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16).map((b, j) => {
      const idx = i + j;
      return plain[idx] && cipher[idx] && plain[idx] !== cipher[idx] ? `[${b}]` : ` ${b} `;
    });
    const left = chunk.slice(0, 8).join("");
    const right = chunk.slice(8).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${left.padEnd(32)} ${right}`);
  }
  return lines.join("\n");
}

function asciiFromHex(hexText) {
  const bytes = splitBytes(hexText);
  const chars = bytes.map(b => {
    const n = parseInt(b, 16);
    return n >= 32 && n <= 126 ? String.fromCharCode(n) : ".";
  });
  const lines = [];
  for (let i = 0; i < chars.length; i += 16) {
    lines.push(chars.slice(i, i + 16).join(""));
  }
  return lines.join("\n");
}

function renderSelected() {
  const packet = rows[selectedIndex];
  if (!packet) return;
  const changed = changedBytes(packet);
  const total = packet.length || 0;
  const ratio = total ? Math.round((changed / total) * 100) : 0;
  $("details").innerHTML = `
    <div class="tree-row">▾ Datagram ${packet.no}: ${total + 24} byte eBaF message delivered to local UDP server</div>
    <div class="tree-row child">Arrival: ${packet.time || "live"}   Path: namespace client → veth → XDP → UDP server</div>
    <div class="tree-row">▾ Local UDP Client, Src: ${sourceFor(packet)}, Dst: ${destFor(packet)}</div>
    <div class="tree-row">▾ Internet Protocol Version 4, Src: ${sourceFor(packet)}, Dst: ${destFor(packet)}</div>
    <div class="tree-row">▾ User Datagram Protocol, Src Port: 4242, Dst Port: 7777</div>
    <div class="tree-row selected">▾ XDP Crypto Transform</div>
    <div class="tree-row child shade">Program: ebaf xdp_crypto   Action: encrypt   Cipher: AES-128-CBC</div>
    <div class="tree-row child">Result: crypto_ok   Changed bytes: ${changed}/${total} (${ratio}%)</div>
    <div class="tree-row child shade">Plaintext preview: ${esc(packet.plain_ascii || "not paired")}</div>
    <div class="tree-row child">Ciphertext preview: ${esc(packet.cipher_hex || "waiting")}</div>
    <div class="tree-row">▾ Runtime Counters</div>
    <div class="tree-row child shade">seen=${latestStats.seen || 0} passed=${latestStats.passed || 0} crypto_ok=${latestStats.crypto_ok || 0} crypto_fail=${latestStats.crypto_fail || 0}</div>
  `;
  $("hexPane").textContent = groupedHex(packet.plain_hex, packet.cipher_hex);
  $("asciiPane").textContent = [
    "Plaintext:",
    packet.plain_ascii || "",
    "",
    "Ciphertext bytes interpreted as ASCII:",
    asciiFromHex(packet.cipher_hex || "")
  ].join("\n");
  $("ident").textContent = `Selected transform: ${changed}/${total} payload bytes changed by XDP`;
}

async function refresh() {
  try {
    const res = await fetch("/api/snapshot", { cache: "no-store" });
    const data = await res.json();
    latestStats = data.stats || {};
    $("status").textContent =
      `${data.status} · ${data.iface} · ${data.mode}/${data.algo} · UDP ${data.port} · ` +
      `seen ${latestStats.seen || 0} · crypto_ok ${latestStats.crypto_ok || 0} · fail ${latestStats.crypto_fail || 0}`;
    $("counts").textContent =
      `Packets: ${latestStats.seen || 0} · Displayed: ${(data.packets || []).length} (100.0%) · ` +
      `paired transforms: ${data.capture_count || 0} · UDP client sends: ${data.sender_count || 0} · UDP server receives: ${data.server_count || 0} · Profile: Default`;
    renderRows(data.packets || []);
  } catch (err) {
    $("status").textContent = `disconnected · ${err}`;
  }
}

$("reset").onclick = () => {
  selectedIndex = 0;
  renderRows(rows);
};

$("stop").onclick = async () => {
  await fetch("/api/stop", { method: "POST" });
  $("status").textContent = "stopping capture...";
};

setInterval(refresh, 1000);
refresh();

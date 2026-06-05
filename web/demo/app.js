import { api } from "./api.js";
import { matchesFilter } from "./filters.js";

let allPackets = [];
let rows = [];
let selectedIndex = 0;
let selectedSeq = null;
let firstTsNs = 0;
let latestStats = {};
let lastSnapshot = {};
let artifacts = { experiments: [], packet_proof: {}, physical_profiles: [], physical_tc_demos: [] };
let autoRefresh = true;
let tableFontSize = 12;

const $ = (id) => document.getElementById(id);

function esc(text) {
  return String(text ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}

function shortInfo(packet) {
  const sampleBytes = (packet.cipher_hex || "").replace(/\s+/g, "").length / 2;
  const srcPort = packet.src_port || 0;
  const dstPort = packet.dst_port || 7777;
  return `TC transparent UDP media ${packet.action || "encrypt"} ${packet.algo || "cbc-aes"} | ${srcPort}->${dstPort} | payload=${packet.payload_len || packet.length || 0}B | cipher sample=${sampleBytes}B`;
}

function splitBytes(hexText) {
  return (hexText || "").replace(/\s+/g, "").match(/.{1,2}/g) || [];
}

function groupedHex(cipherHex) {
  const bytes = splitBytes(cipherHex);
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16).map(b => ` ${b} `);
    const left = chunk.slice(0, 8).join("");
    const right = chunk.slice(8).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${left.padEnd(32)} ${right}`);
  }
  return lines.join("\n");
}

function asciiFromHex(hexText) {
  const chars = splitBytes(hexText).map(b => {
    const n = parseInt(b, 16);
    return n >= 32 && n <= 126 ? String.fromCharCode(n) : ".";
  });
  const lines = [];
  for (let i = 0; i < chars.length; i += 16) {
    lines.push(chars.slice(i, i + 16).join(""));
  }
  return lines.join("\n");
}

function packetNumber(packet, idx) {
  if (Number.isFinite(packet.seq)) return packet.seq + 1;
  return allPackets.length - idx;
}

function packetTime(packet, idx) {
  if (packet.ts_ns) {
    if (!firstTsNs) firstTsNs = packet.ts_ns;
    return ((packet.ts_ns - firstTsNs) / 1e9).toFixed(6);
  }
  return (idx * 0.05).toFixed(6);
}

function filteredPackets() {
  const filter = $("filterInput").value;
  return allPackets.filter(packet => matchesFilter(packet, filter, shortInfo(packet)));
}

function keepSelection() {
  if (selectedSeq !== null) {
    const idx = rows.findIndex(packet => packet.seq === selectedSeq);
    if (idx >= 0) {
      selectedIndex = idx;
      return;
    }
  }
  selectedIndex = Math.min(selectedIndex, Math.max(rows.length - 1, 0));
  if (rows[selectedIndex]) selectedSeq = rows[selectedIndex].seq;
}

function renderRows() {
  const tbody = $("packets");
  rows = filteredPackets().slice(0, 160).map((packet, idx) => ({
    ...packet,
    no: packetNumber(packet, idx),
    rel: packetTime(packet, idx),
  }));

  keepSelection();
  tbody.innerHTML = rows.map((packet, idx) => `
    <tr class="${idx === selectedIndex ? "selected" : ""} ${esc(packet.action || "encrypt")}" data-idx="${idx}">
      <td>${packet.no}</td>
      <td>${packet.rel}</td>
      <td>${esc(packet.src || "")}</td>
      <td>${esc(packet.dst || "")}</td>
      <td>UDP/EBAF</td>
      <td>${packet.length || 0}</td>
      <td>${esc(packet.action || "encrypt")}</td>
      <td>${esc(shortInfo(packet))}</td>
    </tr>
  `).join("");

  tbody.querySelectorAll("tr").forEach(tr => {
    tr.onclick = () => {
      selectedIndex = Number(tr.dataset.idx);
      selectedSeq = rows[selectedIndex]?.seq ?? null;
      renderRows();
    };
  });

  renderSelected();
  renderFooter();
}

function renderSelected() {
  const packet = rows[selectedIndex];
  if (!packet) {
    $("details").innerHTML = `<div class="tree-row">Frame: waiting for live TC events</div>`;
    $("hexPane").textContent = "";
    $("asciiPane").textContent = "";
    return;
  }

  $("details").innerHTML = `
    <div class="tree-row">Frame ${packet.no}: live TC transparent UDP media event</div>
    <div class="tree-row child">Arrival: ${packet.time || "live"}   Source: ebaf-crypto --hook tc --transparent --jsonl</div>
    <div class="tree-row child shade">Media payload preview: ${esc(packet.plain_ascii || "metadata unavailable")}</div>
    <div class="tree-row">Internet Protocol Version 4, Src: ${esc(packet.src || "")}, Dst: ${esc(packet.dst || "")}</div>
    <div class="tree-row">User Datagram Protocol, Src Port: ${packet.src_port || 0}, Dst Port: ${packet.dst_port || 7777}</div>
    <div class="tree-row selected">TC Transparent Crypto Event</div>
    <div class="tree-row child shade">Action: ${esc(packet.action || "encrypt")}   Cipher: ${esc(packet.algo || "cbc-aes")}</div>
    <div class="tree-row child">Result: crypto_ok   Payload length: ${packet.payload_len || 0}   Data length: ${packet.length || 0}</div>
    <div class="tree-row child shade">Kernel timestamp ns: ${packet.ts_ns || 0}</div>
    <div class="tree-row child">Trace id: ${esc(packet.trace_id || "-")}</div>
    <div class="tree-row child">Cipher sample: ${esc(packet.cipher_hex || "waiting")}</div>
    <div class="tree-row">▾ Runtime Counters</div>
    <div class="tree-row child shade">seen=${latestStats.seen || 0} passed=${latestStats.passed || 0} crypto_ok=${latestStats.crypto_ok || 0} crypto_fail=${latestStats.crypto_fail || 0} malformed=${latestStats.malformed || 0}</div>
  `;
  $("hexPane").textContent = groupedHex(packet.cipher_hex);
  $("asciiPane").textContent = [
    "Cipher sample as ASCII:",
    packet.cipher_ascii || asciiFromHex(packet.cipher_hex || ""),
    "",
    "JSON fields:",
    `src=${packet.src || ""}`,
    `dst=${packet.dst || ""}`,
    `src_port=${packet.src_port || 0}`,
    `dst_port=${packet.dst_port || 0}`,
    `payload_len=${packet.payload_len || 0}`,
    `data_len=${packet.length || 0}`,
    `ts_ns=${packet.ts_ns || 0}`,
  ].join("\n");
}

function renderFooter() {
  $("counts").textContent =
    `Packets: ${latestStats.seen || 0} | Displayed: ${rows.length}/${allPackets.length} | ` +
    `TC events: ${lastSnapshot.event_count || lastSnapshot.capture_count || 0} | ` +
    `UDP sends: ${lastSnapshot.sender_count || 0} | UDP receives: ${lastSnapshot.server_count || 0}`;
}

function bestRow(mode) {
  return (artifacts.experiments || [])
    .filter(row => row.name && row.name.includes(mode) && row.pps_median)
    .sort((a, b) => Number(b.pps_median) - Number(a.pps_median))[0];
}

function latest(items) {
  return (items || []).slice().sort((a, b) => Number(b.created_at || 0) - Number(a.created_at || 0))[0] || {};
}

function boolText(value) {
  return value ? "yes" : "no";
}

function renderReport() {
  const profile = latest(artifacts.physical_profiles);
  const physical = latest(artifacts.physical_tc_demos);
  const proof = artifacts.packet_proof || {};
  const full = bestRow("tc_encrypt_decrypt_");
  const rowsHtml = (artifacts.experiments || []).filter(row => row.pps_median).map(row => `
    <tr>
      <td>${esc(row.name)}</td>
      <td>${esc(row.hook)}</td>
      <td>${esc(row.mode)}</td>
      <td>${esc(row.payload_bytes || "-")}</td>
      <td>${esc(row.pps_median || "-")}</td>
      <td>${esc(row.crypto_ok || "0")}</td>
      <td>${esc(row.malformed || "0")}</td>
    </tr>
  `).join("");

  $("reportBody").innerHTML = `
    <div class="report-grid">
      <div>
        <h3>Physical NIC Profile</h3>
        <p>iface=${esc(profile.interface || "-")} mtu=${esc(profile.link?.mtu || "-")} driver=${esc(profile.driver || "-")}</p>
        <p>${esc(profile.link?.state || "link state unavailable")}</p>
      </div>
      <div>
        <h3>Physical TC Media</h3>
        <p>iface=${esc(physical.interface || "-")} peer=${esc(physical.peer_ip || "-")} sent=${esc(physical.sent || 0)} crypto_ok=${esc(physical.stats?.crypto_ok || 0)} malformed=${esc(physical.stats?.malformed || 0)}</p>
        <p>scope=${esc(physical.scope || "run sudo make physical-tc-demo")}</p>
      </div>
      <div>
        <h3>Crypto Proof</h3>
        <p>ciphertext_differs=${boolText(proof.ciphertext_differs)} decrypt_matches=${boolText(proof.decrypt_matches)}</p>
        <p>cipher=${esc(String(proof.encrypted_sample_hex || "-").slice(0, 32))}</p>
      </div>
      <div>
        <h3>TC UDP Full Path</h3>
        <p>${full ? `name=${esc(full.name)} pps_median=${esc(full.pps_median)} payload=${esc(full.payload_bytes || "-")}B` : "run sudo make experiment"}</p>
        <p>local veth TC transparent UDP media benchmark, not physical NIC hardware benchmark</p>
      </div>
    </div>
    <table class="report-table">
      <thead><tr><th>Name</th><th>Hook</th><th>Mode</th><th>Payload</th><th>PPS median</th><th>crypto_ok</th><th>malformed</th></tr></thead>
      <tbody>${rowsHtml || `<tr><td colspan="7">No experiment CSV loaded</td></tr>`}</tbody>
    </table>
  `;
}

function renderArtifactPanes() {
  const proof = artifacts.packet_proof || {};
  const profile = latest(artifacts.physical_profiles);
  const physical = latest(artifacts.physical_tc_demos);
  const tc = bestRow("tc_encrypt_");
  const full = bestRow("tc_encrypt_decrypt_");
  $("captureSummary").textContent =
    `iface=${lastSnapshot.iface || "-"} seen=${latestStats.seen || 0} ok=${latestStats.crypto_ok || 0} malformed=${latestStats.malformed || 0}`;
  $("proofSummary").textContent =
    proof.decrypt_matches
      ? `plain="${proof.plaintext}" cipher=${String(proof.encrypted_sample_hex || "").slice(0, 16)}... decrypt=match`
      : "run sudo make packet-proof";
  $("benchmarkSummary").textContent =
    full
      ? `local-veth TC UDP median pps: encrypt ${tc?.pps_median || "-"} | full path ${full.pps_median}`
      : "run sudo make experiment";
  $("physicalSummary").textContent =
    physical.stats
      ? `${physical.interface} to ${physical.peer_ip} | TC UDP media ok=${physical.stats.crypto_ok || 0} | malformed=${physical.stats.malformed || 0}`
      : "run sudo make physical-tc-demo";
  renderReport();
}

function setFilter(value) {
  $("filterInput").value = value;
  selectedSeq = null;
  selectedIndex = 0;
  renderRows();
}

function downloadSnapshot() {
  const blob = new Blob([JSON.stringify(lastSnapshot, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `ebaf-snapshot-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

async function refresh() {
  if (!autoRefresh) return;
  try {
    const data = await api.snapshot();
    lastSnapshot = data;
    latestStats = data.stats || {};
    allPackets = data.packets || [];
    const tsValues = allPackets.map(p => p.ts_ns).filter(Boolean);
    if (tsValues.length) firstTsNs = Math.min(...tsValues);
    $("status").textContent =
      `status ${data.status} | ${data.iface} | ${data.mode}/${data.algo} | UDP ${data.port} | ` +
      `seen ${latestStats.seen || 0} | crypto_ok ${latestStats.crypto_ok || 0} | fail ${latestStats.crypto_fail || 0}`;
    renderRows();
    renderArtifactPanes();
  } catch (err) {
    $("status").textContent = `API error | ${err.message || err}`;
  }
}

async function loadArtifacts() {
  try {
    artifacts = await api.artifacts();
    renderArtifactPanes();
  } catch {
    artifacts = { experiments: [], packet_proof: {}, physical_profiles: [], physical_tc_demos: [] };
  }
}

async function loadCapabilities() {
  try {
    const caps = await api.capabilities();
    const filters = caps.filters || [];
    $("exprMenu").innerHTML = filters.map(filter => `
      <button data-filter="${esc(filter.value)}">${esc(filter.label)}</button>
    `).join("");
    $("exprMenu").querySelectorAll("button").forEach(button => {
      button.onclick = () => {
        setFilter(button.dataset.filter || "");
        $("exprMenu").classList.add("hidden");
      };
    });
  } catch {
    $("exprMenu").innerHTML = `<button data-filter="">backend filters unavailable</button>`;
  }
}

$("start").onclick = () => {
  autoRefresh = true;
  $("pause").textContent = "pause";
  refresh();
};

$("pause").onclick = () => {
  autoRefresh = !autoRefresh;
  $("pause").textContent = autoRefresh ? "pause" : "resume";
};

$("reset").onclick = () => {
  selectedSeq = null;
  selectedIndex = 0;
  firstTsNs = 0;
  renderRows();
};

$("stop").onclick = async () => {
  await api.stop();
  $("status").textContent = "stopping capture...";
};

$("openSnapshot").onclick = () => window.open("/api/snapshot", "_blank");
$("saveSnapshot").onclick = downloadSnapshot;
$("reportToggle").onclick = () => {
  $("reportPanel").classList.toggle("hidden");
  renderReport();
};
$("reportClose").onclick = () => $("reportPanel").classList.add("hidden");
$("find").onclick = () => $("filterInput").focus();
$("applyFilter").onclick = () => setFilter($("filterInput").value);
$("clearFilter").onclick = () => setFilter("");
$("filterInput").addEventListener("keydown", event => {
  if (event.key === "Enter") setFilter($("filterInput").value);
});

$("expression").onclick = () => $("exprMenu").classList.toggle("hidden");

$("prevPacket").onclick = () => {
  selectedIndex = Math.max(selectedIndex - 1, 0);
  selectedSeq = rows[selectedIndex]?.seq ?? null;
  renderRows();
};

$("nextPacket").onclick = () => {
  selectedIndex = Math.min(selectedIndex + 1, Math.max(rows.length - 1, 0));
  selectedSeq = rows[selectedIndex]?.seq ?? null;
  renderRows();
};

$("zoomIn").onclick = () => {
  tableFontSize = Math.min(tableFontSize + 1, 18);
  document.documentElement.style.setProperty("--mono-size", `${tableFontSize}px`);
};

$("zoomOut").onclick = () => {
  tableFontSize = Math.max(tableFontSize - 1, 10);
  document.documentElement.style.setProperty("--mono-size", `${tableFontSize}px`);
};

setInterval(refresh, 1000);
setInterval(loadArtifacts, 5000);
loadCapabilities();
loadArtifacts();
refresh();

const history = [];
let selected = null;
let latestPackets = [];

function byId(id) { return document.getElementById(id); }

function setText(id, text) { byId(id).textContent = text; }

function drawChart() {
  const canvas = byId("chart");
  const ctx = canvas.getContext("2d");
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#0d141c";
  ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = "#263545";
  ctx.lineWidth = 1;
  for (let i = 0; i < 5; i++) {
    const y = 20 + i * ((h - 40) / 4);
    ctx.beginPath(); ctx.moveTo(40, y); ctx.lineTo(w - 10, y); ctx.stroke();
  }
  const max = Math.max(1, ...history.flatMap(p => [p.pps, p.okr]));
  function line(key, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    history.forEach((p, i) => {
      const x = 40 + i * ((w - 60) / Math.max(history.length - 1, 1));
      const y = h - 20 - (p[key] / max) * (h - 45);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();
  }
  line("pps", "#64b5f6");
  line("okr", "#33d17a");
  ctx.fillStyle = "#89a1b7";
  ctx.font = "12px ui-monospace";
  ctx.fillText(`max ${max}/s`, 8, 18);
  ctx.fillStyle = "#64b5f6"; ctx.fillText("pps", 48, h - 6);
  ctx.fillStyle = "#33d17a"; ctx.fillText("crypto_ok/s", 92, h - 6);
}

function renderPackets(packets) {
  latestPackets = packets || [];
  const body = byId("packets");
  body.innerHTML = "";
  latestPackets.slice(0, 40).forEach((p, idx) => {
    const tr = document.createElement("tr");
    tr.onclick = () => selectPacket(p);
    tr.innerHTML = `<td>${p.time || ""}</td><td>${p.state || ""}</td><td>${p.length || 0}</td>` +
      `<td>${(p.plain_ascii || "").slice(0, 48)}</td><td>${(p.cipher_hex || "").slice(0, 72)}</td>`;
    body.appendChild(tr);
    if (!selected && idx === 0) selectPacket(p);
  });
}

function selectPacket(packet) {
  selected = packet;
  setText("plainAscii", packet.plain_ascii || "(captured packet already encrypted)");
  setText("plainHex", packet.plain_hex || "(not available for captured row)");
  setText("cipherHex", packet.cipher_hex || "(waiting for transformed packet)");
}

async function update() {
  try {
    const res = await fetch("/api/snapshot", { cache: "no-store" });
    const data = await res.json();
    setText("status", `${data.status} | iface ${data.iface} | ${data.mode} ${data.algo} UDP/${data.port} | uptime ${data.uptime_sec}s`);
    setText("seen", data.stats.seen || 0);
    setText("ok", data.stats.crypto_ok || 0);
    setText("fail", data.stats.crypto_fail || 0);
    setText("pps", data.pps || 0);
    setText("okr", data.crypto_ok_rate || 0);
    history.push({ pps: data.pps || 0, okr: data.crypto_ok_rate || 0 });
    while (history.length > 90) history.shift();
    renderPackets(data.packets);
    drawChart();
  } catch (err) {
    setText("status", `disconnected: ${err}`);
  }
}

byId("reset").onclick = () => {
  history.length = 0;
  selected = null;
  renderPackets(latestPackets);
  drawChart();
};

byId("stop").onclick = async () => {
  await fetch("/api/stop", { method: "POST" });
  setText("status", "stopping...");
};

setInterval(update, 1000);
update();

export function packetText(packet, infoText) {
  return [
    packet.src, packet.dst, packet.src_port, packet.dst_port,
    packet.action, packet.algo, packet.cipher_hex, infoText,
  ].join(" ").toLowerCase();
}

export function matchesFilter(packet, filter, infoText) {
  const f = filter.trim().toLowerCase();
  if (!f || f === "all") return true;
  if (f.includes("ebaf.crypto") && !(packet.cipher_hex || packet.algo)) return false;

  const portMatch = f.match(/udp\.port\s*==\s*(\d+)/);
  if (portMatch) {
    const port = Number(portMatch[1]);
    if (packet.src_port !== port && packet.dst_port !== port) return false;
  }

  const srcMatch = f.match(/ip\.src\s*==\s*([0-9.]+)/);
  if (srcMatch && packet.src !== srcMatch[1]) return false;

  const dstMatch = f.match(/ip\.dst\s*==\s*([0-9.]+)/);
  if (dstMatch && packet.dst !== dstMatch[1]) return false;

  const actionMatch = f.match(/action\s*==\s*"?([a-z0-9_-]+)"?/);
  if (actionMatch && String(packet.action || "").toLowerCase() !== actionMatch[1]) return false;

  const algoMatch = f.match(/algo\s*==\s*"?([a-z0-9_-]+)"?/);
  if (algoMatch && String(packet.algo || "").toLowerCase() !== algoMatch[1]) return false;

  const known = /(udp\.port|ebaf\.crypto|ip\.src|ip\.dst|action|algo|&&|\|\||==|"|\(|\))/g;
  const leftovers = f.replace(known, " ").replace(/[0-9.]+/g, " ").trim();
  if (!leftovers) return true;
  return packetText(packet, infoText).includes(leftovers);
}

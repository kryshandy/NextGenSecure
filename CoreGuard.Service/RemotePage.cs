namespace CoreGuard.Service;

/// <summary>
/// Page de contrôle servie au téléphone. La clé d'appareil arrive dans le fragment « #k= » (jamais transmis sur le
/// réseau), est gardée dans le stockage local du téléphone, puis effacée de la barre d'adresse. Chaque ordre est signé
/// HMAC-SHA256(clé, « défi|action ») en JavaScript : SHA-256 est implémenté ici car l'API WebCrypto n'est pas
/// disponible sur une page http:// du réseau local.
/// </summary>
internal static class RemotePage
{
    /// <summary>SHA-256 et HMAC en JavaScript (aussi testés contre .NET par les tests du service).</summary>
    internal const string CryptoJs = """
const K256 = new Uint32Array([
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
function sha256(bytes) {
  const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const len = bytes.length, padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(bytes); padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 4, (len * 8) >>> 0);
  dv.setUint32(padded.length - 8, Math.floor(len / 0x20000000));
  const W = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = W[t - 15], y = W[t - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[t] + W[t]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Uint8Array(32), odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i]);
  return out;
}
function hmacSha256(key, msg) {
  if (key.length > 64) key = sha256(key);
  const k = new Uint8Array(64); k.set(key);
  const inner = new Uint8Array(64 + msg.length), outer = new Uint8Array(96);
  for (let i = 0; i < 64; i++) { inner[i] = k[i] ^ 0x36; outer[i] = k[i] ^ 0x5c; }
  inner.set(msg, 64);
  outer.set(sha256(inner), 64);
  return sha256(outer);
}
function hex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join(""); }
function utf8(text) { return new TextEncoder().encode(text); }
function fromBase64Url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
""";

    internal static readonly string Html = """
<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CoreGuard — contrôle à distance</title>
<style>
body{margin:0;font:16px/1.45 system-ui,"Segoe UI",sans-serif;background:#0f1320;color:#e8ebf3}
main{max-width:460px;margin:0 auto;padding:22px 18px}
h1{font-size:22px;margin:0 0 4px}.sub{color:#9aa3b8;margin:0 0 18px;font-size:14px}
.card{background:#161b2b;border-radius:14px;padding:16px;margin-bottom:14px}
.etat{display:flex;justify-content:space-between;margin:6px 0}.on{color:#ff6b6b;font-weight:600}.off{color:#4cc38a;font-weight:600}
button{display:block;width:100%;margin:10px 0;padding:15px;border:0;border-radius:12px;font:600 17px system-ui;color:#fff;background:#2a3350}
button.rouge{background:#d6334a}button.vert{background:#1f8f5f}button.ambre{background:#b0700d}
#msg{min-height:1.4em;color:#c5cad8;font-size:14px}.warn{color:#ffb4b4}
</style></head><body><main>
<h1>CoreGuard</h1><p class="sub">Contrôle à distance du PC (réseau local ou point d'accès du PC, sans Internet)</p>
<div class="card" id="pas-associe" hidden><p class="warn">Ce téléphone n'est pas associé. Dans CoreGuard sur le PC : Réglages &gt; Contrôle à distance &gt; « Associer un téléphone », puis scannez le QR code.</p></div>
<div class="card" id="panneau" hidden>
  <div class="etat"><span>Verrouillage du PC</span><span id="e-lock">…</span></div>
  <div class="etat"><span>Mode Paranoïa</span><span id="e-par">…</span></div>
  <button onclick="ordre('status')">Actualiser l'état</button>
  <button class="rouge" onclick="ordre('lock')">Verrouiller le PC</button>
  <button class="vert" onclick="confirmer('unlock','Déverrouiller le PC à distance ?')">Déverrouiller le PC</button>
  <button class="ambre" onclick="ordre('paranoia-on')">Activer le Mode Paranoïa</button>
  <button onclick="confirmer('paranoia-off','Désactiver le Mode Paranoïa ?')">Désactiver le Mode Paranoïa</button>
</div>
<p id="msg"></p>
</main><script>
""" + CryptoJs + """
const m = location.hash.match(/k=([A-Za-z0-9_-]{20,})/);
if (m) { localStorage.setItem("coreguard-key", m[1]); history.replaceState(null, "", location.pathname); }
const cle = localStorage.getItem("coreguard-key");
document.getElementById(cle ? "panneau" : "pas-associe").hidden = false;
function afficher(s) {
  if (!s) return;
  const l = document.getElementById("e-lock"), p = document.getElementById("e-par");
  l.textContent = s.lockdown ? "Verrouillé" : "Déverrouillé"; l.className = s.lockdown ? "on" : "off";
  p.textContent = s.paranoia ? "Actif" : "Désactivé"; p.className = s.paranoia ? "on" : "off";
}
function confirmer(action, question) { if (confirm(question)) ordre(action); }
async function ordre(action) {
  const msg = document.getElementById("msg");
  msg.textContent = "Envoi…";
  try {
    const d = await (await fetch("/api/challenge", { method: "POST" })).json();
    const mac = hex(hmacSha256(fromBase64Url(cle), utf8(d.challenge + "|" + action)));
    const r = await (await fetch("/api/command", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: d.challenge, action, mac }) })).json();
    msg.textContent = r.message || (r.ok ? "OK" : "Refusé");
    afficher(r.status);
  } catch (e) { msg.textContent = "PC injoignable : êtes-vous sur le même Wi-Fi ou sur le point d'accès du PC ?"; }
}
if (cle) ordre("status");
</script></body></html>
""";
}

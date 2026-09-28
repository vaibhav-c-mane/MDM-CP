"use strict";

/* ================= helpers ================= */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => t.classList.remove("show"), 2400);
}

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  let data;
  try { data = await res.json(); } catch { data = { ok: false, error: `Server error (${res.status})` }; }
  if (!data.ok) throw new Error(data.error || "Request failed");
  return data;
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function downloadB64(name, b64, type = "application/octet-stream") {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  downloadBlob(name, new Blob([bytes], { type }));
}

function downloadBlob(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function busy(btn, fn, label = "Working…") {
  const old = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> ${label}`;
  try { return await fn(); } finally { btn.disabled = false; btn.innerHTML = old; }
}

const fmtSize = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
const fmtDate = (iso) => {
  if (!iso) return "not stated";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
};
const fmtDay = (iso) => { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleDateString(undefined, { dateStyle: "medium" }); };
const errorBox = (e) => `<div class="error">${esc(e.message || e)}</div>`;

async function readFile(file) {
  if (file.size > 10 * 1024 * 1024) throw new Error(`${file.name} is larger than 10 MB`);
  return { name: file.name, size: file.size, b64: toBase64(await file.arrayBuffer()) };
}

/* ================= tabs ================= */
function showTab(name) {
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  $$(".panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${name}`));
  history.replaceState(null, "", `#${name}`);
  window.scrollTo({ top: 0 });
}
$$(".tab").forEach((t) => t.addEventListener("click", () => showTab(t.dataset.tab)));
$$("[data-tab-link]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); resetVerify(); showTab("verify"); }));

/* ================= drop zones ================= */
function setupDrop(zone, input, onFile) {
  input.addEventListener("change", () => { if (input.files[0]) onFile(input.files[0]); input.value = ""; });
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault(); zone.classList.remove("over");
    if (e.dataTransfer.files[0]) onFile(e.dataTransfer.files[0]);
  });
}

function chip(el, file, onRemove) {
  if (!file) { el.hidden = true; el.innerHTML = ""; return; }
  el.hidden = false;
  el.innerHTML = `<span aria-hidden="true">📄</span><span class="name">${esc(file.name)}</span><span class="muted small">${fmtSize(file.size)}</span><button type="button" aria-label="Remove">✕</button>`;
  $("button", el).onclick = onRemove;
}

/* ================= VERIFY ================= */
const state = { doc: null, sig: null, lastReport: null, note: "" };

function refreshVerifyForm() {
  chip($("#doc-chip"), state.doc, () => { state.doc = null; refreshVerifyForm(); });
  chip($("#sig-chip"), state.sig, () => { state.sig = null; refreshVerifyForm(); });
  $("#drop-doc").hidden = !!state.doc;
  $("#drop-sig").hidden = !!state.sig;
  if (state.sig) $("#sig-slot").open = true;
  $("#verify-btn").disabled = !state.doc;
}

const SIG_EXT = /\.(p7s|sig|pkcs7)$/i;
setupDrop($("#drop-doc"), $("#doc-input"), async (f) => {
  try {
    const file = await readFile(f);
    if (SIG_EXT.test(f.name) && state.doc) state.sig = file; else state.doc = file;
    refreshVerifyForm();
  } catch (e) { toast(e.message); }
});
setupDrop($("#drop-sig"), $("#sig-input"), async (f) => {
  try { state.sig = await readFile(f); refreshVerifyForm(); } catch (e) { toast(e.message); }
});

$("#verify-btn").addEventListener("click", (e) => busy(e.currentTarget, runVerify, "Checking…"));

async function runVerify() {
  const out = $("#verify-result");
  try {
    const report = await api("/api/verify", {
      document_b64: state.doc.b64, filename: state.doc.name,
      signature_b64: state.sig ? state.sig.b64 : null,
    });
    state.lastReport = report;
    out.innerHTML = renderReport(report);
    state.note = "";
  } catch (err) {
    state.note = "";
    out.innerHTML = `<div class="result-top"><button class="btn" data-again>← Verify another file</button></div>${errorBox(err)}`;
  }
  $("#verify-start").hidden = true;
  out.hidden = false;
  window.scrollTo({ top: 0 });
}

function resetVerify() {
  state.doc = null; state.sig = null;
  refreshVerifyForm();
  $("#verify-result").hidden = true;
  $("#verify-start").hidden = false;
}

const VICON = { VALID: "✓", UNKNOWN: "!", INVALID: "✕", ERROR: "✕", NO_SIGNATURE: "?" };
const CICON = { pass: "✓", warn: "!", fail: "✕" };
const VLABEL = { VALID: "Valid", UNKNOWN: "Needs attention", INVALID: "Not valid" };

function mathsBlock(m) {
  if (!m) return "";
  const rows = Object.entries(m).filter(([k]) => k !== "formula")
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
  return `<button type="button" class="maths-toggle" data-toggle>Show the maths</button>
    <dl class="maths" hidden>${m.formula ? `<div class="formula">${esc(m.formula)}</div>` : ""}${rows}</dl>`;
}

function renderCoverage(cov) {
  if (!cov) return "";
  const [a, b, c, d] = cov.byte_range;
  const total = cov.file_bytes;
  const extra = total - (c + d);
  const pct = (x) => `${Math.max((x / total) * 100, 0)}%`;
  return `
    <h3 class="subhead">What the signature covers</h3>
    <div class="coverage">
      <div class="bar" role="img" aria-label="Byte ranges covered by the signature">
        <div class="seg-signed" style="width:${pct(b)}"></div>
        <div class="seg-hole" style="width:${pct(c - b)}"></div>
        <div class="seg-signed" style="width:${pct(d)}"></div>
        ${extra > 0 ? `<div class="seg-extra" style="width:${pct(extra)}"></div>` : ""}
      </div>
      <div class="legend">
        <span><i style="background:var(--good)"></i>Signed bytes 0–${b - 1} and ${c}–${c + d - 1}</span>
        <span><i style="background:var(--muted)"></i>Gap holding the signature (${c - b} bytes)</span>
        ${extra > 0 ? `<span><i style="background:var(--warn)"></i>${extra} bytes added later (not signed)</span>` : ""}
        <span>File size ${total} bytes</span>
      </div>
    </div>`;
}

function renderChain(chain) {
  if (!chain || !chain.length) return "";
  // Show from the root at the top down to the signer.
  const items = [...chain].reverse();
  let html = `<h3 class="subhead">Certificate chain (who vouches for whom)</h3><div class="chain">`;
  items.forEach((c, i) => {
    const role = i === items.length - 1 ? "Signer" : c.trusted_root ? "Root CA" : c.is_ca ? "Certificate authority" : "Certificate";
    const badge = c.trusted_root ? `<span class="badge VALID">trusted root</span>`
      : (c.subject === c.issuer ? `<span class="badge UNKNOWN">self-signed, not trusted</span>` : "");
    html += `<div class="cert"><div class="cname">${esc(c.name)} <span class="badge neutral">${role}</span> ${badge}</div>
      <div class="cmeta">Valid ${esc(fmtDay(c.valid_from))} → ${esc(fmtDay(c.valid_to))} · issued by ${esc(c.issuer)}</div></div>`;
    const below = items[i + 1];
    if (below) {
      const ok = below.signature_ok;
      html += `<div class="link ${ok === true ? "ok" : ok === false ? "bad" : ""}"><span class="arrow">↓</span>
        <span>${ok === true ? "signed this certificate — checked ✓" : ok === false ? "signature on the certificate below is wrong ✕" : "signed the certificate below"}
        ${mathsBlock(below.maths)}</span></div>`;
    }
  });
  const leaf = chain[0];
  if (leaf && leaf.issuer !== leaf.subject && chain.length === 1) {
    html = html.replace(`<div class="chain">`, `<div class="chain"><div class="cert"><div class="cname">${esc(leaf.issuer)} <span class="badge INVALID">missing</span></div><div class="cmeta">The issuer's certificate was not found.</div></div><div class="link bad"><span class="arrow">↓</span>?</div>`);
  }
  return html + `</div>`;
}

function renderSignature(s, count) {
  const signer = s.signer || {};
    const facts = [
    ["Signed", `${fmtDate(s.signing_time)}${s.signing_time_source ? ` (${s.signing_time_source})` : ""}`],
    ["Algorithm", s.algorithm || "—"],
    signer.email && ["Email", signer.email],
    signer.issuer && ["Certificate issued by", (signer.issuer.match(/CN=([^,]+)/) || [, signer.issuer])[1]],
    s.reason && ["Reason", s.reason],
    s.location && ["Location", s.location],
  ].filter(Boolean);
  const checks = (s.checks || []).map((c) => `
    <li class="check"><div class="check-row"><span class="cicon ${c.status}">${CICON[c.status]}</span>
      <div class="ctext"><div class="ctitle">${esc(c.title)}</div><div class="cmsg">${esc(c.message)}</div>${mathsBlock(c.maths)}</div></div></li>`).join("");
  return `
    <article class="card sigcard">
      <div class="card-head">
        <h2>${count > 1 ? `Signature ${s.index} of ${count}: ` : "Signature: "}${esc(signer.name || "Unknown signer")}</h2>
        <span class="status"><i class="dot ${s.verdict}"></i>${esc(VLABEL[s.verdict])}</span>
      </div>
      ${s.error ? errorBox(s.error) : ""}
      <table class="kv-table">
        ${signer.organization ? `<tr><th>Organisation</th><td>${esc(signer.organization)}</td></tr>` : ""}
        <tr><th>Type</th><td>${esc(s.kind)}</td></tr>
        ${facts.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("")}
      </table>
      ${checks ? `<h3 class="subhead">Checks</h3><ul class="checks">${checks}</ul>` : ""}
      ${renderCoverage(s.coverage)}
      ${renderChain(s.chain)}
    </article>`;
}

function renderReport(r) {
  const f = r.file || {};
  return `
    <div class="result-top">
      <button class="btn" data-again>← Verify another file</button>
      ${r.signatures && r.signatures.length ? `<button class="btn small" data-report>Download report (JSON)</button>` : ""}
    </div>
    ${state.note ? `<div class="sample-note"><strong>About this sample:</strong> ${esc(state.note)}</div>` : ""}
    <section class="card verdict ${r.overall}">
      <div class="verdict-bar">
        <span class="vicon" aria-hidden="true">${VICON[r.overall] || "?"}</span>
        <div><h2>${esc(r.headline)}</h2><p>${esc(r.summary)}</p></div>
      </div>
      <table class="kv-table">
        <tr><th>File</th><td>${esc(f.name)}</td></tr>
        <tr><th>Type</th><td>${esc(f.type || "")}</td></tr>
        <tr><th>Size</th><td>${fmtSize(f.size || 0)}</td></tr>
        <tr><th>SHA-256</th><td class="mono small">${esc(f.sha256 || "")}</td></tr>
      </table>
    </section>
    ${(r.signatures || []).map((s) => renderSignature(s, r.signatures.length)).join("")}
    <ul class="notes">${(r.notes || []).map((n) => `<li>${esc(n)}</li>`).join("")}</ul>`;
}

$("#verify-result").addEventListener("click", (e) => {
  if (e.target.closest("[data-again]")) { resetVerify(); return; }
  if (e.target.closest("[data-report]")) {
    downloadBlob("verification-report.json", new Blob([JSON.stringify(state.lastReport, null, 2)], { type: "application/json" }));
    return;
  }
  const t = e.target.closest("[data-toggle]");
  if (t) {
    const box = t.nextElementSibling;
    box.hidden = !box.hidden;
    t.textContent = box.hidden ? "Show the maths" : "Hide the maths";
  }
});

/* ----- samples ----- */
let samples = [];
async function loadSamples() {
  const list = $("#sample-list");
  try {
    samples = (await api("/api/samples")).samples;
  } catch (err) { list.innerHTML = errorBox(err); return; }
  const groups = {};
  samples.forEach((s) => (groups[s.group] = groups[s.group] || []).push(s));
  const label = { VALID: "Valid", UNKNOWN: "Needs attention", INVALID: "Not valid", NO_SIGNATURE: "No signature" };
  list.innerHTML = `<table class="sample-table">
    <thead><tr><th>Sample</th><th>Files</th><th>Expected result</th><th></th></tr></thead>
    <tbody>${Object.entries(groups).map(([g, items]) => `
      <tr class="group-row"><td colspan="4">${esc(g)}</td></tr>
      ${items.map((s) => `<tr>
        <td><strong>${esc(s.title)}</strong><div class="muted small">${esc(s.explanation)}</div></td>
        <td class="mono small">${esc(s.file)}${s.signature ? "<br>" + esc(s.signature) : ""}</td>
        <td><span class="status"><i class="dot ${s.expected}"></i>${label[s.expected] || s.expected}</span></td>
        <td class="right"><button class="btn small sample" data-sample="${esc(s.id)}">Verify</button></td>
      </tr>`).join("")}`).join("")}</tbody></table>`;
}

async function fetchSampleFile(name) {
  const res = await fetch(`/samples/${encodeURIComponent(name)}`);
  if (!res.ok) throw new Error(`Sample file ${name} is missing`);
  const buf = await res.arrayBuffer();
  return { name, size: buf.byteLength, b64: toBase64(buf) };
}

$("#sample-list").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-sample]");
  if (!btn) return;
  const s = samples.find((x) => x.id === btn.dataset.sample);
  try {
    state.doc = await fetchSampleFile(s.file);
    state.sig = s.signature ? await fetchSampleFile(s.signature) : null;
    state.note = s.explanation;
    refreshVerifyForm();
    await runVerify();
  } catch (err) { toast(err.message); }
});

/* ================= SIGN ================= */
let identities = [];
async function loadIdentities(selectId) {
  const box = $("#identity-list");
  try { identities = (await api("/api/identities")).identities; } catch (err) { box.innerHTML = errorBox(err); return; }
  const current = selectId || ($("input[name=signer]:checked") || {}).value || (identities[0] || {}).id;
  box.innerHTML = identities.map((i) => `
    <label class="identity"><input type="radio" name="signer" value="${esc(i.id)}" ${i.id === current ? "checked" : ""}>
      <span class="avatar" aria-hidden="true">${esc(i.name.charAt(0).toUpperCase())}</span>
      <span class="who"><strong>${esc(i.name)}</strong><span>${esc([i.organization, i.email].filter(Boolean).join(" · "))}</span>
      <span>Certificate by ${esc((i.issuer.match(/CN=([^,]+)/) || [, i.issuer])[1])}, valid to ${esc(fmtDay(i.valid_to))}</span></span></label>`).join("")
    || `<p class="muted">No signers yet.</p>`;
}

$("#identity-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = e.currentTarget;
  busy($("button[type=submit]", f), async () => {
    try {
      const res = await api("/api/identities", { name: f.name.value, email: f.email.value, organization: f.organization.value });
      await loadIdentities(res.identity.id);
      f.reset();
      f.closest("details").open = false;
      toast(`Certificate issued to ${res.identity.name}`);
    } catch (err) { toast(err.message); }
  }, "Generating key…");
});

$$("[data-sign-mode]").forEach((b) => b.addEventListener("click", () => {
  $$("[data-sign-mode]").forEach((x) => x.classList.toggle("on", x === b));
  $("#sign-pdf-form").hidden = b.dataset.signMode !== "pdf";
  $("#sign-file-form").hidden = b.dataset.signMode !== "file";
  $("#sign-result").innerHTML = "";
}));

let signFile = null;
setupDrop($("#drop-sign"), $("#sign-input"), async (f) => {
  try { signFile = await readFile(f); } catch (err) { toast(err.message); return; }
  chip($("#sign-chip"), signFile, () => { signFile = null; chip($("#sign-chip"), null); $("#drop-sign").hidden = false; });
  $("#drop-sign").hidden = true;
});

function currentSigner() {
  const r = $("input[name=signer]:checked");
  if (!r) throw new Error("Choose who is signing first");
  return r.value;
}

function showSigned(html, onVerify) {
  const box = $("#sign-result");
  box.innerHTML = `<div class="done">${html}<div class="actions"><button class="btn primary small" data-verify-now>Verify it now</button></div></div>`;
  $("[data-verify-now]", box).onclick = onVerify;
}

$("#sign-pdf-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = e.currentTarget;
  busy($("button[type=submit]", f), async () => {
    try {
      const res = await api("/api/sign/pdf", { signer: currentSigner(), title: f.title.value, text: f.text.value,
        reason: f.reason.value, location: f.location.value });
      downloadB64(res.filename, res.file_b64, "application/pdf");
      showSigned(`<strong>Signed by ${esc(res.signer)}.</strong><p>${esc(res.filename)} has been downloaded.</p>`, () => {
        state.doc = { name: res.filename, size: atob(res.file_b64).length, b64: res.file_b64 };
        state.sig = null;
        showTab("verify"); refreshVerifyForm(); runVerify();
      });
    } catch (err) { $("#sign-result").innerHTML = errorBox(err); }
  }, "Signing…");
});

$("#sign-file-form").addEventListener("submit", (e) => {
  e.preventDefault();
  busy($("button[type=submit]", e.currentTarget), async () => {
    try {
      if (!signFile) throw new Error("Choose a file to sign");
      const res = await api("/api/sign/file", { signer: currentSigner(), file_b64: signFile.b64, filename: signFile.name });
      downloadB64(res.filename, res.file_b64, "application/pkcs7-signature");
      const doc = signFile;
      showSigned(`<strong>Signed by ${esc(res.signer)}.</strong><p>${esc(res.filename)} has been downloaded. Keep it next to ${esc(doc.name)}: both are needed to verify.</p>`, () => {
        state.doc = doc;
        state.sig = { name: res.filename, size: atob(res.file_b64).length, b64: res.file_b64 };
        showTab("verify"); refreshVerifyForm(); runVerify();
      });
    } catch (err) { $("#sign-result").innerHTML = errorBox(err); }
  }, "Signing…");
});

/* ================= LEARN ================= */
const table = (heads, rows, hl) => `<div class="table-wrap"><table><thead><tr>${heads.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
  rows.map((r, i) => `<tr class="${hl && hl(i) ? "hl" : ""}">${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;

const MATH = {
  rsa: (d) => `<ol class="steps">${d.steps.map((s) => `<li>${esc(s)}</li>`).join("")}
      <li>Sign: s = m^d mod n = ${esc(d.m)}^${esc(d.d)} mod ${esc(d.n)} = ${esc(d.s)}</li>
      <li>Verify: s^e mod n = ${esc(d.check)} ${d.check === d.m ? "= m ✓" : "≠ m ✕"}</li></ol>`,
  gcd: (d) => `<p><strong>gcd = ${esc(d.gcd)}</strong></p><p class="bignum">${esc(d.bezout)}</p>
      ${table(["a", "= q ×", "b", "+ r"], d.divisions.map((r) => [r.a, r.q, r.b, r.r]))}`,
  inverse: (d) => d.inverse === null ? `<div class="error">${esc(d.error)}</div>`
    : `<p><strong>${esc(d.a)}⁻¹ mod ${esc(d.n)} = ${esc(d.inverse)}</strong></p><p class="bignum">${esc(d.check)}</p>`,
  modpow: (d) => `<p><strong>Result = ${esc(d.result)}</strong></p>
      <p class="muted small">Exponent in binary <code>${esc(d.binary)}</code> · ${esc(d.multiplications.fast)} multiplications instead of ${esc(d.multiplications.naive)}</p>
      ${d.rows.length ? table(["bit", "b", "base^(2^i) mod n", "result"], d.rows.map((r) => [r.i, r.bit, r.power, r.result]), (i) => d.rows[i].bit === "1") : ""}`,
  prime: (d) => {
    const f = Object.entries(d.fermat).map(([a, ok]) => `a=${a}: ${ok ? "passes" : "fails"}`).join(", ");
    return `<p><strong>${esc(d.n)} is ${d.miller_rabin ? "prime" : "composite"}</strong> (Miller–Rabin)</p>
      ${f ? `<p class="muted small">Fermat test: ${esc(f)}</p>` : ""}
      ${d.fooled_fermat ? `<div class="warning">Carmichael number: it fools the Fermat test, but Miller–Rabin catches it.</div>` : ""}
      ${d.factors.length ? `<p class="muted small">Factors: ${esc(d.factors.join(" × "))}</p>` : ""}`;
  },
  crt: (d) => `<p><strong>x = ${esc(d.x)}</strong> (mod ${esc(d.modulus)})</p><p class="bignum">${esc(d.check)}</p>`,
};

$$("form.math").forEach((form) => form.addEventListener("submit", (e) => {
  e.preventDefault();
  const out = $(".out", form);
  busy($("button[type=submit]", form), async () => {
    try { out.innerHTML = MATH[form.dataset.api](await api(`/api/math/${form.dataset.api}`, Object.fromEntries(new FormData(form)))); }
    catch (err) { out.innerHTML = errorBox(err); }
  });
}));

$("#attack-factor").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = e.currentTarget, out = $(".out", f);
  busy($("button[type=submit]", f), async () => {
    try {
      const d = await api("/api/attacks/factor", { n: f.n.value, e: f.e.value });
      out.innerHTML = d.found ? `<div class="warning">Private key recovered: the attacker can now sign as the owner.</div>
        <dl class="kv"><dt>p</dt><dd>${esc(d.p)}</dd><dt>q</dt><dd>${esc(d.q)}</dd><dt>φ(n)</dt><dd>${esc(d.phi)}</dd><dt>d = e⁻¹ mod φ(n)</dt><dd>${esc(d.d)}</dd></dl>`
        : `<div class="warning">Could not factor n within the step limit.</div>`;
    } catch (err) { out.innerHTML = errorBox(err); }
  });
});

$("#attack-forgery").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = e.currentTarget, out = $(".out", f);
  busy($("button[type=submit]", f), async () => {
    try {
      const d = await api("/api/attacks/forgery", { m1: f.m1.value, m2: f.m2.value });
      const m = d.multiplicative, x = d.existential;
      const yn = (v) => v ? `<span class="badge INVALID">accepted</span>` : `<span class="badge VALID">rejected</span>`;
      out.innerHTML = `<p class="muted small">Fresh 64-bit key: n = ${esc(d.public_key.n)}</p>
        <dl class="kv"><dt>real s(m1 = ${esc(m.m1)})</dt><dd>${esc(m.s1)}</dd><dt>real s(m2 = ${esc(m.m2)})</dt><dd>${esc(m.s2)}</dd>
        <dt>forged s(${esc(m.m3)}) = s1·s2</dt><dd>${esc(m.s3)}</dd></dl>
        <p>Textbook RSA: ${yn(m.textbook_accepts)} · Hash-then-sign: ${yn(m.hashed_accepts)}</p>
        <p class="small">Existential forgery (pick s, publish m = s^e): textbook ${yn(x.textbook_accepts)} · hashed ${yn(x.hashed_accepts)}</p>`;
    } catch (err) { out.innerHTML = errorBox(err); }
  });
});

/* ================= start ================= */
refreshVerifyForm();
loadSamples();
loadIdentities();
api("/api/trust").then((d) => {
  $("#trust-info").textContent = `Trusted roots: ${d.roots.map((r) => r.name).join(", ") || "none"}`;
}).catch(() => {});
const start = location.hash.slice(1);
if (["verify", "sign", "learn"].includes(start)) showTab(start);

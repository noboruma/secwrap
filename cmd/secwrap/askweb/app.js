"use strict";

const $ = (id) => document.getElementById(id);
const busy = new Set(); // ids with an answer in flight
const chosenDir = new Map(); // id -> folder picked in the select (survives re-renders)
let lastJSON = "";

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids) e.append(k);
  return e;
}

const time = (t) => new Date(t).toLocaleTimeString();
const dest = (r) => r.path || r.remote;
const what = (r) => r.access === "exec"
  ? `${r.comm || "?"} (pid ${r.pid}) · ${(r.args || []).join(" ") || "exec"}`
  : r.path
  ? `${r.comm || "?"} (pid ${r.pid}) · file ${r.access}`
  : `${r.comm || "?"} (pid ${r.pid}) · ${r.proto || "?"} ${r.kind}`;

// forget undoes an answer: the next such call asks again.
async function forget(id) {
  try {
    const res = await fetch(`api/requests/${id}/forget`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    if (!res.ok && res.status !== 409) alert(`Could not forget: ${await res.text()}`);
  } catch (e) {
    alert(`Could not forget: ${e}`);
  } finally {
    poll();
  }
}

async function answer(id, allow, dir) {
  busy.add(id);
  render(JSON.parse(lastJSON || "[]"));
  try {
    const res = await fetch(`api/requests/${id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(dir ? { allow, dir } : { allow }),
    });
    if (!res.ok && res.status !== 409) alert(`Could not answer: ${await res.text()}`);
  } catch (e) {
    alert(`Could not answer: ${e}`);
  } finally {
    busy.delete(id);
    poll();
  }
}

// "Yes, every read/write under [folder]": a folder rule (reads and writes
// are separate rules).
function folderRow(r, dis) {
  if (!r.dirs || !r.dirs.length) return "";
  const sel = el("select", { "aria-label": "folder", onchange: (e) => chosenDir.set(r.id, e.target.value), ...dis },
    ...r.dirs.map((d) => el("option", { value: d }, d)));
  if (chosenDir.has(r.id)) sel.value = chosenDir.get(r.id);
  return el("div", { class: "folder" },
    el("span", {}, `or allow every ${r.access} under`),
    sel,
    el("button", { class: "yes small", onclick: () => answer(r.id, true, sel.value), ...dis }, "Allow folder"));
}

function render(items) {
  const pending = items.filter((r) => r.status === "pending").reverse(); // oldest first
  const done = items.filter((r) => r.status !== "pending");

  const p = $("pending");
  p.replaceChildren();
  if (!pending.length) p.append(el("div", { class: "empty" }, "Nothing waiting."));
  for (const r of pending) {
    const dis = busy.has(r.id) ? { disabled: "" } : {};
    p.append(el("div", { class: "card pending" },
      el("div", {},
        el("div", { class: "dest" }, r.path ? el("span", { class: `tag ${r.access[0]}` }, r.access.toUpperCase()) : "", dest(r)),
        el("div", { class: "meta" }, `${what(r)} · ${time(r.time)}`)),
      el("div", { class: "actions" },
        el("button", { class: "yes", onclick: () => answer(r.id, true), ...dis }, "Yes"),
        el("button", { class: "no", onclick: () => answer(r.id, false), ...dis }, "No")),
      folderRow(r, dis)));
  }

  const h = $("history");
  h.replaceChildren();
  if (!done.length) {
    h.append(el("div", { class: "empty" }, "No requests yet."));
  } else {
    const label = { allowed: "allowed", denied: "denied", gone: "process gone", covered: "allowed (folder rule)", forgotten: "forgotten: will ask again" };
    h.append(el("table", {}, ...done.map((r) =>
      el("tr", {},
        el("td", { class: "time" }, time(r.time)),
        el("td", { class: "mono" }, dest(r), r.folder ? el("div", { class: "sub-folder" }, `folder rule: ${r.folder}/`) : ""),
        el("td", { class: "hide-sm" }, what(r)),
        el("td", { class: "status-cell" }, el("span", { class: `badge ${r.status}` }, label[r.status] || r.status),
          r.status === "allowed" || r.status === "denied"
            ? el("button", { class: "ghost small", title: "Undo this answer: the next such request asks again", onclick: () => forget(r.id) }, "Forget")
            : "")))));
  }

  document.title = pending.length ? `(${pending.length}) secwrap: answer needed` : `secwrap: ${alive === false ? "dead session" : "requests"}`;
}

// The session itself: alive (its command runs, questions can be answered)
// or dead (ended or crashed: its record and SBOMs stay viewable).
let alive = null;
async function pollSession() {
  try {
    const res = await fetch("api/session", { cache: "no-store" });
    if (!res.ok) throw new Error(res.status);
    const s = await res.json();
    alive = s.alive;
    $("title").textContent = `secwrap: ${s.id}`;
    $("state").hidden = false;
    $("state").className = `state ${s.alive ? "alive" : "dead"}`;
    $("state-pill").textContent = s.alive ? "alive" : "dead";
    $("state-what").textContent = s.target;
    $("state-detail").textContent = `${s.user} · ask: ${s.ask} · ${s.detail}`
      + (s.history ? ` · recorded in ${s.history}` : "");
  } catch {
    $("state").hidden = true;
  }
}

async function poll() {
  pollSession();
  try {
    const res = await fetch("api/requests", { cache: "no-store" });
    if (!res.ok) throw new Error(res.status);
    const text = await res.text();
    $("status").textContent = alive === false
      ? "This session is dead: nothing left to answer. Its record stays until deleted (secwrap session)."
      : "Live: updates every second.";
    $("status").className = "status";
    if (text !== lastJSON) {
      lastJSON = text;
      render(JSON.parse(text));
    }
  } catch {
    $("status").textContent = "The web page is not reachable: it comes back when a secwrap with --web runs.";
    $("status").className = "status off";
  }
}

// Binaries executed (--sbom, on by default with the web page). null: the
// section stays hidden. "SBOM" opens the component list in place.
let lastBins = "";
const openSBOM = new Set(); // binary ids shown expanded
const sbomCache = new Map(); // binary id -> parsed SBOM

async function toggleSBOM(id) {
  if (openSBOM.has(id)) {
    openSBOM.delete(id);
  } else {
    openSBOM.add(id);
    if (!sbomCache.has(id)) {
      try {
        const res = await fetch(`api/binaries/${id}/sbom`, { cache: "no-store" });
        sbomCache.set(id, res.ok ? await res.json() : null);
      } catch { sbomCache.set(id, null); }
    }
  }
  lastBins = ""; // force a re-render
  pollBinaries();
}

function sbomTable(bom) {
  if (!bom) return el("div", { class: "empty" }, "Could not load the SBOM.");
  const comps = bom.components || [];
  if (!comps.length) return el("div", { class: "empty" }, "No components found (static binary, or no package information).");
  return el("table", { class: "comps" },
    el("tr", {}, ...["Component", "Version", "Type", "Package URL"].map((h) => el("th", {}, h))),
    ...comps.map((c) => el("tr", {},
      el("td", { class: "mono" }, c.name || ""),
      el("td", { class: "mono" }, c.version || ""),
      el("td", {}, c.type || ""),
      el("td", { class: "mono purl" }, c.purl || ""))));
}
async function pollBinaries() {
  let text;
  try {
    const res = await fetch("api/binaries", { cache: "no-store" });
    if (!res.ok) return;
    text = await res.text();
  } catch { return; }
  if (text === lastBins) return;
  lastBins = text;
  const bins = JSON.parse(text);
  $("binaries-section").hidden = bins === null;
  if (!bins) return;
  const box = $("binaries");
  box.replaceChildren();
  if (!bins.length) {
    box.append(el("div", { class: "empty" }, "No binary executed yet."));
    return;
  }
  const rows = [];
  for (const b of bins) {
    const links = [];
    if (b.status === "done") {
      links.push(el("button", { class: "ghost small", onclick: () => toggleSBOM(b.id) }, openSBOM.has(b.id) ? "Hide SBOM" : "SBOM"),
        el("a", { href: `api/binaries/${b.id}/sbom?download=1` }, "JSON"));
    } else {
      links.push(el("span", { class: `badge ${b.status}`, title: b.error || "" }, b.status === "error" ? "error" : "building…"));
    }
    if (b.sha256) {
      // Opened by the browser: only the hash leaves this machine, nothing is uploaded.
      links.push(el("a", { href: `https://www.virustotal.com/gui/file/${b.sha256}`, target: "_blank", rel: "noopener noreferrer",
        title: "Look the SHA-256 up on VirusTotal" }, "VirusTotal"));
    }
    rows.push(el("tr", {},
      el("td", { class: "time" }, time(b.firstSeen)),
      el("td", { class: "mono" }, b.path,
        el("div", { class: "sub-folder" }, `${b.comm} (pid ${b.pid})${b.sha256 ? " · sha256 " + b.sha256.slice(0, 12) : ""}${b.language ? " · " + b.language : ""}`)),
      el("td", { class: "num hide-sm" }, b.status === "done" ? `${b.components} comp.` : "", el("div", {}, `×${b.execs}`)),
      el("td", { class: "links" }, ...links)));
    if (openSBOM.has(b.id)) {
      rows.push(el("tr", { class: "sbom-row" }, el("td", { colspan: "4" }, sbomTable(sbomCache.get(b.id)))));
    }
  }
  box.append(el("table", {}, ...rows));
}

poll();
// #sbom-ID opens that binary's SBOM (a link to share).
const deep = /^#sbom-(\d+)$/.exec(location.hash);
if (deep) toggleSBOM(Number(deep[1]));
else pollBinaries();
setInterval(poll, 1000);
setInterval(pollBinaries, 2000);

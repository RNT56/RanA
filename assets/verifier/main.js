// assets/verifier/main.js — drives the RanA export verifier viewer
// (assets/verifier/index.html) entirely client-side.
//
// This page makes NO network request of any kind (D24): wasm_exec.js and
// rana-verify.wasm are loaded once from same-origin release assets, and
// every export file the user provides is read locally via the File API
// (FileReader/ArrayBuffer) and handed straight to WebAssembly. Nothing is
// uploaded, logged, or phoned home. See docs/TRUST.md §8 for the algorithm
// this is presenting the result of, and cmd/rana-verify-wasm for the Go
// side of the JS boundary this file talks to.
//
// Expected files (docs/TRUST.md §7), matched by filename:
//   manifest.json, events.cbor, segments.cbor, checkpoints.cbor, pubkey.pem
"use strict";

const CANONICAL_NAMES = [
  "manifest.json",
  "events.cbor",
  "segments.cbor",
  "checkpoints.cbor",
  "pubkey.pem",
];

const state = {
  files: {}, // filename -> ArrayBuffer
  wasmReady: false,
};

function $(id) {
  return document.getElementById(id);
}

function setStatus(msg) {
  $("wasm-status").textContent = msg;
}

async function loadWasm() {
  setStatus("Loading verifier engine...");
  const go = new Go();
  const resp = await fetch("rana-verify.wasm");
  if (!resp.ok) {
    throw new Error("failed to fetch rana-verify.wasm: HTTP " + resp.status);
  }
  const buf = await resp.arrayBuffer();
  const result = await WebAssembly.instantiate(buf, go.importObject);
  // go.run never resolves (main blocks on `select {}`), so don't await it —
  // just start it and rely on the global it installs.
  go.run(result.instance);
  state.wasmReady = true;
  setStatus("Verifier engine loaded. Drop your export files below.");
}

function renderFileList() {
  const list = $("file-list");
  list.innerHTML = "";
  for (const name of CANONICAL_NAMES) {
    const li = document.createElement("li");
    const have = Object.prototype.hasOwnProperty.call(state.files, name);
    li.textContent = (have ? "✓ " : "✗ ") + name;
    li.className = have ? "have" : "missing";
    list.appendChild(li);
  }
}

function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

async function ingestFiles(fileList) {
  for (const file of fileList) {
    if (!CANONICAL_NAMES.includes(file.name)) {
      continue; // ignore unrelated files (e.g. the .jsonl convenience copies)
    }
    state.files[file.name] = await readFileAsArrayBuffer(file);
  }
  renderFileList();
  updateRunButton();
}

function updateRunButton() {
  const btn = $("run-verify");
  const haveEvents = Object.prototype.hasOwnProperty.call(state.files, "events.cbor");
  btn.disabled = !(state.wasmReady && haveEvents);
}

function classNameForVerdict(verdict) {
  switch (verdict) {
    case "OK":
      return "verdict-ok";
    case "BROKEN":
      return "verdict-broken";
    default:
      return "verdict-incomplete";
  }
}

function summaryForVerdict(result) {
  switch (result.verdict) {
    case "OK": {
      const n = result.unattestedTail ? result.unattestedTail.length : 0;
      if (n === 0) {
        return "Every event, segment, and checkpoint signature in this export checked out. The recorded history is intact.";
      }
      return (
        "The signed portion of this export is intact. " +
        n +
        " segment(s) are sealed and hash-linked but not yet covered by a signed checkpoint " +
        "(a normal, expected state for recent data — not tampering)."
      );
    }
    case "BROKEN":
      return (
        "This export FAILED verification: " +
        (result.reason || "a mismatch was detected") +
        ". Treat the recorded history in this export as untrustworthy."
      );
    case "INCOMPLETE":
      return (
        "Verification could not be completed: " +
        (result.reason || "an artifact was missing or unreadable") +
        ". This is not evidence of tampering — supply the missing artifact and retry."
      );
    default:
      return "";
  }
}

function renderResult(result) {
  const box = $("result");
  box.className = classNameForVerdict(result.verdict);
  box.hidden = false;

  $("result-verdict").textContent = result.verdict;
  $("result-summary").textContent = summaryForVerdict(result);

  const details = $("result-details");
  details.innerHTML = "";

  if (result.verdict === "BROKEN" && result.reasonClass) {
    const li = document.createElement("li");
    li.textContent = "Reason class: " + result.reasonClass;
    details.appendChild(li);
  }

  if (result.unattestedTail && result.unattestedTail.length > 0) {
    for (const u of result.unattestedTail) {
      const li = document.createElement("li");
      li.textContent =
        "Unattested tail: session=" + u.session + " seg=" + u.seg +
        " (sealed, hash-linked, not yet checkpoint-signed)";
      details.appendChild(li);
    }
  }

  if (result.externalPrevNotes && result.externalPrevNotes.length > 0) {
    for (const idx of result.externalPrevNotes) {
      const li = document.createElement("li");
      li.textContent =
        "External-prev: checkpoint " + idx +
        "'s prev_checkpoint_hash refers to a checkpoint outside this export " +
        "(expected for a single-session export whose ledger has earlier sessions).";
      details.appendChild(li);
    }
  }
}

function runVerify() {
  if (!state.wasmReady) {
    return;
  }
  const result = globalThis.ranaVerifyExport(state.files);
  renderResult(result);
}

function setupDropZone() {
  const zone = $("drop-zone");
  const input = $("file-input");

  zone.addEventListener("click", () => input.click());

  input.addEventListener("change", (ev) => {
    ingestFiles(ev.target.files);
  });

  ["dragenter", "dragover"].forEach((evt) => {
    zone.addEventListener(evt, (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      zone.classList.add("dragging");
    });
  });

  ["dragleave", "drop"].forEach((evt) => {
    zone.addEventListener(evt, (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      zone.classList.remove("dragging");
    });
  });

  zone.addEventListener("drop", (ev) => {
    const dt = ev.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      ingestFiles(dt.files);
    }
  });
}

function main() {
  renderFileList();
  setupDropZone();
  $("run-verify").addEventListener("click", runVerify);

  loadWasm().catch((err) => {
    setStatus("Failed to load verifier engine: " + err.message);
  });
}

main();

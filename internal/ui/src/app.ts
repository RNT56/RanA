// RanA timeline app. Served static (hand-maintained alongside src/app.ts so
// go:embed works without a Node build). No modules, no inline script (CSP
// default-src 'self'). Wired to the real token-gated API: /api/sessions,
// /api/events, /api/alerts, /api/stream (SSE).
(function () {
  "use strict";

  // --- token: injected into the page by the Go handler (index.html meta),
  // with ?token= as a fallback for the initial navigation. ---
  function getToken() {
    var m = document.querySelector('meta[name="rana-token"]');
    var t = (m && m.getAttribute("content")) || "";
    if (t && t.indexOf("__RANA") !== 0) return t;
    return new URLSearchParams(location.search).get("token") || "";
  }
  var TOKEN = getToken();

  function getJSON(path) {
    return fetch(path, { headers: { Authorization: "Bearer " + TOKEN } }).then(function (r) {
      if (!r.ok) throw new Error(path + ": " + r.status);
      return r.json();
    });
  }
  function streamURL(session) {
    return "/api/stream?session=" + encodeURIComponent(session) + "&token=" + encodeURIComponent(TOKEN);
  }

  // --- event classification (mirrors internal/ui/src/types.ts) ---
  function laneFor(ev) {
    var t = ev.type || "";
    if (t.indexOf("proc.") === 0 || t === "session.start" || t === "session.end") return "process";
    if (t.indexOf("fs.") === 0) return "filesystem";
    if (t.indexOf("net.") === 0 || t === "unix.connect") return "network";
    return "other";
  }
  function isMarker(ev) { return (ev.type || "").indexOf("marker.") === 0; }
  function isGap(ev) { return ev.type === "gap"; }
  function isAlert(ev) { return (ev.type || "").indexOf("alert.") === 0; }
  // severity: alert.* and sensitive-reads carry the signal.
  function sevOf(ev) {
    var t = ev.type || "";
    if (t === "alert.sensitive_read" || t === "alert.cgroup_escape") return "crit";
    if (t === "alert.escape_precursor") return "crit";
    if (isAlert(ev)) return "warn";
    if (t === "fs.sensitive_read") return "warn";
    return null;
  }

  var LANES = [
    { key: "process", label: "PROC", cssVar: "--proc" },
    { key: "filesystem", label: "FILE", cssVar: "--fs" },
    { key: "network", label: "NET", cssVar: "--net" },
  ];
  function cssv(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

  // --- time: ts_wall is ns; JSON loses sub-microsecond precision above 2^53,
  // which is irrelevant to positioning and HH:MM:SS labels. ---
  function tsOf(ev) { return Number(ev.ts_wall || ev.ts_mono || 0); }
  function fmtTime(ns) {
    var d = new Date(ns / 1e6);
    function p(n) { return String(n).padStart(2, "0"); }
    return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }
  function shortId(id) { return id && id.length > 10 ? id.slice(0, 6) + "…" + id.slice(-4) : id; }
  function el(id) { return document.getElementById(id); }
  function esc(s) { var d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }

  // ===================== canvas river =====================
  var PAD_L = 56, PAD_R = 18, PAD_T = 30, LANE_H = 76;

  function River(canvas, onSelect, onHover) {
    this.c = canvas; this.ctx = canvas.getContext("2d");
    this.events = []; this.min = 0; this.max = 1; this.hits = [];
    this.dpr = Math.max(1, window.devicePixelRatio || 1);
    this.onSelect = onSelect; this.onHover = onHover;
    var self = this;
    canvas.addEventListener("mousemove", function (e) { self.move(e); });
    canvas.addEventListener("mouseleave", function () { self.onHover(null); });
    canvas.addEventListener("click", function (e) { var ev = self.pick(e); if (ev) self.onSelect(ev); });
  }
  River.prototype.setEvents = function (evs) {
    this.events = evs.slice();
    var lo = Infinity, hi = -Infinity;
    for (var i = 0; i < evs.length; i++) { var t = tsOf(evs[i]); if (t < lo) lo = t; if (t > hi) hi = t; }
    if (!isFinite(lo)) { lo = 0; hi = 1; }
    this.min = lo; this.max = hi > lo ? hi : lo + 1;
    this.resize();
  };
  River.prototype.add = function (ev) {
    this.events.push(ev);
    var t = tsOf(ev); if (t > this.max) this.max = t; if (t < this.min) this.min = t;
    this.draw();
  };
  River.prototype.resize = function () {
    var w = this.c.clientWidth, h = PAD_T + LANES.length * LANE_H + 8;
    this.c.style.height = h + "px";
    this.c.width = Math.floor(w * this.dpr); this.c.height = Math.floor(h * this.dpr);
    this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    this.w = w; this.h = h; this.draw();
  };
  River.prototype.x = function (t) { var span = this.max - this.min || 1; return PAD_L + (t - this.min) / span * (this.w - PAD_L - PAD_R); };
  River.prototype.laneY = function (key) { var i = 0; for (var k = 0; k < LANES.length; k++) if (LANES[k].key === key) i = k; return PAD_T + i * LANE_H + LANE_H / 2 - 8; };
  River.prototype.draw = function () {
    var ctx = this.ctx, w = this.w, h = this.h; if (!w) return;
    ctx.clearRect(0, 0, w, h);
    var mono = cssv("--mono") || "monospace";
    // lanes
    for (var i = 0; i < LANES.length; i++) {
      var yTop = PAD_T + i * LANE_H;
      if (i % 2 === 0) { ctx.fillStyle = "rgba(255,255,255,.012)"; ctx.fillRect(PAD_L - 8, yTop, w - PAD_L - PAD_R + 8, LANE_H); }
      var by = this.laneY(LANES[i].key) + 8;
      ctx.strokeStyle = cssv("--line-soft"); ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(PAD_L, by); ctx.lineTo(w - PAD_R, by); ctx.stroke();
      ctx.fillStyle = cssv("--faint"); ctx.font = "600 10px " + mono; ctx.textBaseline = "middle";
      ctx.fillText(LANES[i].label, 6, this.laneY(LANES[i].key) + 8);
    }
    // time grid
    ctx.font = "10px " + mono; ctx.textBaseline = "alphabetic";
    for (var g = 0; g <= 6; g++) {
      var t = this.min + (this.max - this.min) * g / 6, gx = this.x(t);
      ctx.strokeStyle = "rgba(255,255,255,.03)"; ctx.beginPath(); ctx.moveTo(gx, PAD_T - 6); ctx.lineTo(gx, h - 6); ctx.stroke();
      ctx.fillStyle = cssv("--faint"); ctx.fillText(fmtTime(t), gx - 18, PAD_T - 12);
    }
    // gaps (loud)
    for (var q = 0; q < this.events.length; q++) {
      var ge = this.events[q]; if (!isGap(ge)) continue;
      var gx1 = this.x(tsOf(ge)) - 6, gx2 = gx1 + 12;
      ctx.fillStyle = "rgba(89,98,120,.18)"; ctx.fillRect(gx1, PAD_T - 4, gx2 - gx1, h - PAD_T);
      ctx.strokeStyle = "rgba(89,98,120,.5)"; ctx.setLineDash([3, 4]);
      ctx.beginPath(); ctx.moveTo((gx1 + gx2) / 2, PAD_T - 4); ctx.lineTo((gx1 + gx2) / 2, h - 8); ctx.stroke(); ctx.setLineDash([]);
    }
    // marker guide lines
    for (var mI = 0; mI < this.events.length; mI++) {
      var me = this.events[mI]; if (!isMarker(me)) continue;
      var mx = this.x(tsOf(me)); ctx.strokeStyle = "rgba(108,147,240,.22)"; ctx.setLineDash([2, 4]);
      ctx.beginPath(); ctx.moveTo(mx, PAD_T - 4); ctx.lineTo(mx, h - 8); ctx.stroke(); ctx.setLineDash([]);
    }
    // events
    this.hits = [];
    for (var e = 0; e < this.events.length; e++) {
      var ev = this.events[e]; if (isGap(ev)) continue;
      var lane = laneFor(ev); if (lane === "other" && !isMarker(ev) && !isAlert(ev)) lane = "process";
      if (isAlert(ev)) lane = "network";
      var ex = this.x(tsOf(ev)), ey = this.laneY(lane), sev = sevOf(ev);
      var color = sev === "crit" ? cssv("--crit") : sev === "warn" ? cssv("--warn") : cssv(laneVar(lane));
      var r = sev === "crit" ? 7 : sev === "warn" ? 5.5 : isMarker(ev) ? 4 : 3.6;
      if (sev) { ctx.beginPath(); ctx.arc(ex, ey, r + 5, 0, 7); ctx.fillStyle = sev === "crit" ? "rgba(255,107,114,.14)" : "rgba(242,176,74,.13)"; ctx.fill(); }
      ctx.beginPath(); ctx.arc(ex, ey, r, 0, 7);
      ctx.fillStyle = isMarker(ev) ? cssv("--bg") : color; ctx.fill();
      if (isMarker(ev)) { ctx.lineWidth = 1.6; ctx.strokeStyle = cssv("--proc"); ctx.stroke(); }
      if (sev === "crit") { ctx.lineWidth = 1.6; ctx.strokeStyle = cssv("--crit"); ctx.stroke(); }
      this.hits.push({ x: ex, y: ey, r: r + 6, ev: ev });
    }
  };
  function laneVar(key) { for (var i = 0; i < LANES.length; i++) if (LANES[i].key === key) return LANES[i].cssVar; return "--faint"; }
  River.prototype.pick = function (e) {
    var rc = this.c.getBoundingClientRect(), mx = e.clientX - rc.left, my = e.clientY - rc.top, best = null, bd = 1e9;
    for (var i = 0; i < this.hits.length; i++) { var hb = this.hits[i], dx = hb.x - mx, dy = hb.y - my, d = dx * dx + dy * dy; if (d < hb.r * hb.r && d < bd) { bd = d; best = hb.ev; } }
    return best;
  };
  River.prototype.move = function (e) { var ev = this.pick(e); this.c.style.cursor = ev ? "pointer" : "default"; this.onHover(ev, e.clientX, e.clientY); };

  // ===================== app =====================
  function App() {
    var self = this;
    this.events = []; this.alerts = []; this.session = ""; this.maxIdx = 0; this.es = null;
    this.tooltip = el("tooltip");
    this.river = new River(el("river"), function (ev) { self.showDetail(ev); }, function (ev, x, y) { self.tip(ev, x, y); });
    window.addEventListener("resize", function () { self.river.resize(); });
  }
  App.prototype.start = function () {
    var self = this;
    if (!TOKEN) { el("hint").textContent = "no access token — open the URL rana printed (it carries ?token=)"; return; }
    getJSON("/api/sessions").then(function (sessions) {
      self.renderRail(sessions);
      if (sessions.length) self.select(sessions[0].id);
      else { el("hint").textContent = "no sessions recorded yet"; el("sess-count").textContent = "0"; }
    }).catch(function (e) { el("hint").textContent = "failed to load sessions: " + e.message; });
  };
  App.prototype.renderRail = function (sessions) {
    var self = this, wrap = el("sessions"); wrap.innerHTML = "";
    el("sess-count").textContent = String(sessions.length);
    sessions.forEach(function (s, i) {
      var b = document.createElement("button");
      b.className = "sess" + (i === 0 ? " on" : ""); b.setAttribute("data-id", s.id);
      var live = !s.ended_ns;
      b.innerHTML =
        '<div class="row1"><span class="prof">' + esc(s.profile || "session") + '</span><span class="id mono">' + esc(shortId(s.id)) + "</span></div>" +
        '<div class="row2"><span class="pip"></span>' + (live ? "recording" : "sealed") + "</div>";
      b.querySelector(".pip").style.background = live ? cssv("--warn") : cssv("--ok");
      b.addEventListener("click", function () {
        var all = wrap.querySelectorAll(".sess"); for (var k = 0; k < all.length; k++) all[k].classList.remove("on");
        b.classList.add("on"); self.select(s.id, s);
      });
      wrap.appendChild(b);
    });
  };
  App.prototype.select = function (id, meta) {
    var self = this; this.session = id; this.maxIdx = 0; this.stopStream();
    el("hint").textContent = "loading " + shortId(id) + "…";
    Promise.all([getJSON("/api/events?session=" + encodeURIComponent(id) + "&after=0"), getJSON("/api/alerts?session=" + encodeURIComponent(id))])
      .then(function (res) {
        self.events = res[0] || []; self.alerts = res[1] || [];
        for (var i = 0; i < self.events.length; i++) if (self.events[i].idx > self.maxIdx) self.maxIdx = self.events[i].idx;
        self.render(meta);
        el("hint").textContent = "hover the river · click an event to inspect it";
        self.startStream(id);
      }).catch(function (e) { el("hint").textContent = "failed to load events: " + e.message; });
  };
  App.prototype.render = function (meta) {
    this.river.setEvents(this.events);
    this.renderSummary();
    this.renderAlerts();
    var start = this.events.length ? this.events[0] : null;
    var pid = start && start.pid ? " · pid " + start.pid : "";
    el("who").textContent = (meta && meta.profile ? meta.profile : "session") + " · " + shortId(this.session) + pid;
    // verify chip: honest — sealed vs recording (chain verification is `rana
    // verify` / rana-mcp, not derivable in the browser).
    var v = el("verify"), sealed = meta ? !!meta.ended_ns : false;
    v.textContent = sealed ? "chain · sealed" : "recording";
    v.className = "chip " + (sealed ? "verified" : "");
    // open the first alert, else the last event
    var focus = this.alerts.length ? this.alerts[this.alerts.length - 1] : (this.events.length ? this.events[this.events.length - 1] : null);
    if (focus) this.showDetail(focus);
  };
  App.prototype.renderSummary = function () {
    var counts = { exec: 0, file: 0, net: 0, sens: 0 };
    for (var i = 0; i < this.events.length; i++) {
      var t = this.events[i].type || "";
      if (t.indexOf("proc.exec") === 0) counts.exec++;
      else if (t.indexOf("fs.") === 0) counts.file++;
      else if (t.indexOf("net.") === 0 || t === "unix.connect") counts.net++;
      if (t === "fs.sensitive_read") counts.sens++;
    }
    var crit = 0; for (var a = 0; a < this.alerts.length; a++) if (sevOf(this.alerts[a]) === "crit") crit++;
    var stats = [
      ["events", this.events.length, ""], ["exec", counts.exec, ""], ["file", counts.file, ""],
      ["connect", counts.net, ""], ["sensitive read", counts.sens, "sens"], ["critical", crit, "alert"],
    ];
    el("summary").innerHTML = stats.map(function (s) {
      return '<div class="stat ' + s[2] + '"><div class="n">' + s[1] + '</div><div class="k">' + s[0] + "</div></div>";
    }).join("");
  };
  App.prototype.renderAlerts = function () {
    var self = this, wrap = el("alerts");
    if (!this.alerts.length) { wrap.innerHTML = '<div class="empty">No alerts in this session.</div>'; return; }
    wrap.innerHTML = "";
    this.alerts.slice().reverse().forEach(function (ev) {
      var sev = sevOf(ev) || "info", d = ev.data || {};
      var tag = (ev.type || "alert").replace("alert.", "").replace(/_/g, " ");
      var row = document.createElement("div"); row.className = "alert";
      row.innerHTML =
        '<div class="sev ' + sev + '"></div><div class="body"><div class="t"><span class="tag ' + sev + '">' + esc(tag) +
        '</span><span class="ts">' + esc(fmtTime(tsOf(ev))) + "</span></div>" +
        "<h4>" + esc(alertHeadline(ev)) + "</h4>" +
        (d.correlated_host ? "<p>correlated host: <span class=\"mono\">" + esc(d.correlated_host) + "</span></p>" : "") + "</div>";
      row.addEventListener("click", function () { self.showDetail(ev); });
      wrap.appendChild(row);
    });
  };
  function alertHeadline(ev) {
    var d = ev.data || {}, t = ev.type || "";
    if (t === "alert.sensitive_read" && d.exfil_precursor) return "Exfil precursor — sensitive read then first contact with " + (d.correlated_host || "a new host");
    if (t === "alert.new_domain") return "First contact — " + (d.qname || d.daddr || "a new domain");
    if (t === "alert.sensitive_read") return "Watchlisted read" + (d.path ? " — " + d.path : "");
    if (t === "alert.cgroup_escape" || t === "alert.escape_precursor") return "Escape — " + t.replace("alert.", "");
    return t;
  }
  App.prototype.showDetail = function (ev) {
    var d = ev.data || {}, sev = sevOf(ev), body = el("detail");
    el("detail-origin").textContent = "origin: " + (ev.origin || "?");
    var rows = "";
    Object.keys(d).forEach(function (k) {
      rows += "<dt>" + esc(k) + '</dt><dd>' + esc(String(d[k])) + "</dd>";
    });
    if (ev.pid) rows += "<dt>pid</dt><dd>" + ev.pid + "</dd>";
    var sevHtml = sev ? '<span class="dsev ' + sev + '">' + (sev === "crit" ? "CRITICAL" : "WATCH") + "</span>" : "";
    body.innerHTML =
      '<div><span class="etype">' + esc(ev.type) + "</span>" + sevHtml + "</div>" +
      '<div class="dtime">idx ' + (ev.idx || 0) + " · seg " + (ev.seg || 0) + " · " + esc(fmtTime(tsOf(ev))) + "</div>" +
      '<dl class="kv">' + rows + "</dl>";
  };
  App.prototype.tip = function (ev, x, y) {
    if (!ev) { this.tooltip.classList.remove("show"); return; }
    this.tooltip.textContent = ev.type + " · +" + ((tsOf(ev) - this.river.min) / 1e9).toFixed(2) + "s";
    this.tooltip.style.left = (x + 12) + "px"; this.tooltip.style.top = (y + 12) + "px";
    this.tooltip.classList.add("show");
  };
  App.prototype.startStream = function (id) {
    var self = this;
    try {
      var es = new EventSource(streamURL(id));
      es.onmessage = function (e) {
        try {
          var ev = JSON.parse(e.data);
          if (self.events.length && ev.idx <= self.maxIdx) return;
          self.maxIdx = Math.max(self.maxIdx, ev.idx);
          self.events.push(ev); self.river.add(ev);
          if (isAlert(ev)) { self.alerts.push(ev); self.renderAlerts(); }
          self.renderSummary();
        } catch (x) { /* never let one bad event kill the tail */ }
      };
      es.onerror = function () { el("hint").textContent = "live tail disconnected — retrying…"; };
      this.es = es;
    } catch (x) { /* SSE unavailable */ }
  };
  App.prototype.stopStream = function () { if (this.es) { this.es.close(); this.es = null; } };

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { new App().start(); });
  else new App().start();
})();

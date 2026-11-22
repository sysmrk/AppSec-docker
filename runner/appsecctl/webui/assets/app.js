/* AppSec Control Center — real API data only; no client-side mocks. */
(() => {
  "use strict";
  const prefix = location.pathname.startsWith("/appsec-api/") ? "/appsec-api" : "";
  const $ = (id) => document.getElementById(id);
  const app = $("app"), loginScreen = $("login-screen"), notice = $("global-notice");
  const state = { user: null, overview: null, view: "overview", result: null };
  const date = (value) => value ? new Date(value).toLocaleString() : "—";
  const text = (value) => value == null || value === "" ? "—" : String(value);
  const node = (tag, css, value) => {
    const n = document.createElement(tag);
    if (css) n.className = css;
    if (value !== undefined) n.textContent = text(value);
    return n;
  };
  const clear = (n) => n.replaceChildren();
  const cell = (row, value, className) => { const c = node("td", className, value); row.appendChild(c); return c; };
  const statusPill = (value) => node("span", "pill " + String(value || "").replace(/[^a-z_]/g, ""), value || "unknown");
  const empty = (body, message, count) => { const r = node("tr"); const c = cell(r, message); c.colSpan = count; c.className = "empty-state"; body.appendChild(r); };
  const button = (label, handler) => { const b = node("button", "text-button", label); b.type = "button"; b.addEventListener("click", handler); return b; };
  const notification = (message, error = false) => {
    notice.textContent = message;
    notice.className = "notice" + (error ? " error" : "");
    notice.hidden = false;
  };
  const quiet = () => { notice.hidden = true; notice.textContent = ""; };
  const request = async (path, options = {}) => {
    const response = await fetch(prefix + path, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Accept": "application/json", "X-Requested-With": "AppSec-Control-Center", ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) },
      ...options
    });
    let body = null;
    try { body = await response.json(); } catch (_) { /* response may not be JSON */ }
    if (!response.ok) {
      const detail = body && body.detail;
      const error = new Error(typeof detail === "string" ? detail : "Request failed (" + response.status + ")");
      error.status = response.status;
      throw error;
    }
    return body;
  };
  function showLogin() {
    state.user = null;
    loginScreen.hidden = false; app.hidden = true;
  }
  function showApp(user) {
    state.user = user;
    $("current-user").textContent = user.username + " · " + user.role;
    loginScreen.hidden = true; app.hidden = false;
  }
  function selectView(view) {
    state.view = view;
    document.querySelectorAll(".view").forEach(v => v.hidden = v.id !== "view-" + view);
    document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === view));
    $("breadcrumb").textContent = ({ overview: "Overview", scan: "Scan image", secrets: "Scan repository", results: "Results", integrations: "Integrations" })[view] || "AppSec";
    quiet();
  }
  async function refreshHealth() {
    try {
      await request("/health");
      $("health-indicator").textContent = "API & database connected";
      $("health-indicator").className = "health ok";
    } catch (_) {
      $("health-indicator").textContent = "Connection unavailable";
      $("health-indicator").className = "health error";
    }
  }
  async function refreshOverview() {
    const data = await request("/api/ui/overview");
    state.overview = data;
    for (const [id, key] of [["stat-total", "total"], ["stat-passed", "passed"], ["stat-policy", "policy_failed"], ["stat-failed", "failed"]]) {
      $(id).textContent = text(data.summary[key] ?? 0);
    }
    const pipelines = $("pipelines-body"); clear(pipelines);
    if (!data.pipelines.length) empty(pipelines, "No image scans have run yet. Start your first real scan.", 6);
    data.pipelines.forEach(p => {
      const r = node("tr");
      cell(r, p.requested_image, "wide-text");
      const s = cell(r, ""); s.appendChild(statusPill(p.status));
      cell(r, p.critical_count); cell(r, p.high_count);
      cell(r, date(p.started_at));
      const actions = cell(r, ""); actions.appendChild(button("Details →", () => openPipeline(p.id)));
      pipelines.appendChild(r);
    });
    const jobs = $("jobs-body"); clear(jobs);
    if (!data.pipeline_jobs.length) empty(jobs, "No image jobs recorded.", 5);
    data.pipeline_jobs.forEach(j => {
      const r = node("tr");
      cell(r, j.requested_image, "wide-text");
      const mode = cell(r, ""); mode.appendChild(statusPill(j.mode || "scan"));
      const s = cell(r, ""); s.appendChild(statusPill(j.status));
      cell(r, date(j.created_at));
      const actions = cell(r, "");
      if (j.pipeline_id) actions.appendChild(button("Results →", () => openPipeline(j.pipeline_id)));
      jobs.appendChild(r);
    });
    const security = $("security-body"); clear(security);
    if (!data.security_jobs.length) empty(security, "No repository security scans recorded.", 5);
    data.security_jobs.forEach(j => {
      const r = node("tr");
      cell(r, j.target, "wide-text");
      const s = cell(r, ""); s.appendChild(statusPill(j.status));
      cell(r, j.finding_count);
      cell(r, date(j.started_at));
      const actions = cell(r, ""); actions.appendChild(button("Results →", () => openSecretJob(j.id)));
      security.appendChild(r);
    });
  }
  async function loadCapabilities() {
    const features = await request("/api/ui/capabilities");
    const option = $("image-mode").querySelector('option[value="patch"]');
    option.disabled = !features.patch_enabled;
    $("patch-warning").textContent = features.patch_enabled
      ? "Advanced operation: Copa will patch and push a new image to the configured registry. Confirm before running."
      : "Patching is disabled. An administrator must start the platform with ./appsec start --patching and configure registry credentials.";
    if (!features.patch_enabled) $("image-mode").value = "scan";
  }
  async function loadProjects() {
    const projects = await request("/api/projects");
    for (const id of ["image-project", "repo-project"]) {
      const select = $(id), previous = select.value;
      while (select.options.length > 1) select.remove(1);
      projects.forEach(p => { const option = document.createElement("option"); option.value = String(p.id); option.textContent = text(p.name); select.appendChild(option); });
      if ([...select.options].some(o => o.value === previous)) select.value = previous;
    }
  }
  function section(root, title) {
    const wrapper = node("div", "detail-section");
    wrapper.appendChild(node("h2", "", title)); root.appendChild(wrapper);
    return wrapper;
  }
  function showMetrics(root, metrics) {
    const group = node("div", "result-stats");
    metrics.forEach(([label, value]) => {
      const b = node("div", "mini-stat");
      b.appendChild(node("strong", "", value));
      b.appendChild(node("span", "", label));
      group.appendChild(b);
    });
    root.appendChild(group);
  }
  function detailsTable(root, columns, rows) {
    const wrap = node("div", "table-wrap"), table = node("table"), head = node("thead"), tr = node("tr");
    columns.forEach(c => tr.appendChild(node("th", "", c[0])));
    head.appendChild(tr); table.appendChild(head);
    const body = node("tbody");
    rows.forEach(item => {
      const row = node("tr");
      columns.forEach(c => cell(row, item[c[1]], "wide-text"));
      body.appendChild(row);
    });
    if (!rows.length) empty(body, "No records found.", columns.length);
    table.appendChild(body); wrap.appendChild(table); root.appendChild(wrap);
  }
  async function loadVulnerabilities(scanId, severity) {
    const holder = $("finding-table");
    holder.textContent = "Loading findings…";
    try {
      const res = await request("/api/ui/scans/" + encodeURIComponent(scanId) + "/vulnerabilities?limit=200" + (severity ? "&severity=" + encodeURIComponent(severity) : ""));
      clear(holder);
      detailsTable(holder, [["CVE", "vulnerability_id"], ["Severity", "severity"], ["Package", "pkg_name"], ["Installed", "installed_version"], ["Fix", "fixed_version"], ["Target", "target"]], res.findings);
      holder.appendChild(node("p", "info-note", "Showing up to 200 findings for the selected scan and severity."));
    } catch (error) { holder.textContent = error.message; }
  }
  async function openPipeline(id) {
    selectView("results");
    const root = $("result-detail"); root.textContent = "Loading pipeline…";
    try {
      const d = await request("/api/ui/pipelines/" + encodeURIComponent(id));
      clear(root); root.className = "panel result-panel";
      const top = node("div", "result-header"), left = node("div");
      left.appendChild(node("h2", "", d.pipeline.requested_image));
      left.appendChild(node("p", "info-note", "Pipeline: " + d.pipeline.id));
      top.appendChild(left); top.appendChild(statusPill(d.pipeline.status)); root.appendChild(top);
      if (d.pipeline.error_message) root.appendChild(node("p", "warning", d.pipeline.error_message));
      const original = d.scans.find(s => s.phase === "original"), patched = d.scans.find(s => s.phase === "patched");
      const resultScan = patched || original;
      if (resultScan) showMetrics(root, [["Critical", resultScan.critical_count], ["High", resultScan.high_count], ["Medium", resultScan.medium_count], ["Low", resultScan.low_count]]);
      if (d.policies.length) {
        const s = section(root, "Policy gate");
        const item = d.policies[0];
        const label = node("p");
        label.appendChild(statusPill(item.status));
        s.appendChild(label);
        if (Array.isArray(item.violations) && item.violations.length) {
          detailsTable(s, [["Severity", "severity"], ["Count", "count"], ["Limit", "limit"]], item.violations);
        }
      }
      if (d.diffs.length) {
        const diff = d.diffs[0];
        const sec = section(root, "Before / after patch");
        showMetrics(sec, [["Fixed CVEs", diff.fixed_count], ["Remaining", diff.remaining_count], ["Introduced", diff.introduced_count]]);
      }
      if (d.scans.length) {
        const sec = section(root, "Vulnerabilities");
        const filters = node("div", "filters"), selector = node("select", "result-filter"), severity = node("select", "result-filter");
        selector.id = "scan-select";
        d.scans.forEach(s => { const opt = node("option", "", s.phase + " · " + s.status); opt.value = String(s.id); selector.appendChild(opt); });
        if (resultScan) selector.value = String(resultScan.id);
        ["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].forEach((value, i) => { const opt = node("option", "", value); opt.value = i === 0 ? "" : value; severity.appendChild(opt); });
        filters.appendChild(selector); filters.appendChild(severity); sec.appendChild(filters);
        const div = node("div"); div.id = "finding-table"; sec.appendChild(div);
        const refresh = () => loadVulnerabilities(selector.value, severity.value);
        selector.addEventListener("change", refresh); severity.addEventListener("change", refresh);
        await refresh();
      }
      const reports = section(root, "Downloads");
      const links = node("div", "results-list");
      [...d.reports.map(r => ({ title: "Report · " + r.format, path: "/api/reports/" + r.id + "/download" })),
        ...d.artifacts.map(a => ({ title: a.kind + " · " + a.format, path: "/api/artifacts/" + a.id + "/download" }))].forEach(info => {
        const a = node("a", "mini-link", info.title + " ↗");
        a.href = prefix + info.path; a.target = "_blank"; a.rel = "noopener";
        links.appendChild(a);
      });
      reports.appendChild(links.childNodes.length ? links : node("p", "info-note", "No downloadable reports yet."));
    } catch (error) { root.textContent = error.message; notification(error.message, true); }
  }
  async function openSecretJob(id) {
    selectView("results");
    const root = $("result-detail"); root.textContent = "Loading repository scan…";
    try {
      const d = await request("/api/ui/security-jobs/" + encodeURIComponent(id));
      clear(root); root.className = "panel result-panel";
      root.appendChild(node("h2", "", d.job.target));
      root.appendChild(node("p", "info-note", "Job: " + d.job.id));
      showMetrics(root, [["Findings", d.job.finding_count], ["High", d.job.high_count], ["Status", d.job.status]]);
      const sec = section(root, "Redacted findings");
      detailsTable(sec, [["Rule", "rule_id"], ["Severity", "severity"], ["Title", "title"], ["Location", "location"]], d.findings);
      sec.appendChild(node("p", "info-note", "Raw secret values and matching evidence are intentionally never displayed."));
      const reports = section(root, "Downloads"), links = node("div", "results-list");
      d.reports.forEach(r => {
        const a = node("a", "mini-link", "Report · " + r.format + " ↗");
        a.href = prefix + "/api/reports/" + r.id + "/download"; a.target = "_blank"; a.rel = "noopener"; links.appendChild(a);
      });
      reports.appendChild(links.childNodes.length ? links : node("p", "info-note", "No generated reports yet."));
    } catch (error) { root.textContent = error.message; notification(error.message, true); }
  }
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault(); $("login-error").textContent = "";
    try {
      const res = await request("/api/auth/login", { method: "POST", body: JSON.stringify({ username: $("username").value, password: $("password").value }) });
      $("password").value = "";
      showApp(res.user); selectView("overview"); await refreshOverview(); await loadProjects(); await loadCapabilities();
    } catch (error) { $("login-error").textContent = error.message; }
  });
  $("logout-button").addEventListener("click", async () => {
    try { await request("/api/auth/logout", { method: "POST" }); } catch (_) { /* session may already be invalid */ }
    showLogin();
  });
  document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => selectView(button.dataset.view)));
  $("refresh-button").addEventListener("click", async () => { quiet(); try { await refreshOverview(); } catch (e) { notification(e.message, true); } });
  $("advanced-toggle").addEventListener("change", () => {
    const enabled = $("advanced-toggle").checked;
    $("advanced-box").hidden = !enabled;
    if (!enabled) $("image-mode").value = "scan";
    $("patch-warning").hidden = $("image-mode").value !== "patch";
  });
  $("image-mode").addEventListener("change", () => $("patch-warning").hidden = $("image-mode").value !== "patch");
  $("image-form").addEventListener("submit", async event => {
    event.preventDefault();
    const mode = $("advanced-toggle").checked ? $("image-mode").value : "scan";
    if (mode === "patch" && !window.confirm("This will attempt to patch an image and push it to the configured registry. Continue?")) return;
    const payload = { image: $("image-reference").value.trim(), mode, confirm_patch: mode === "patch", project_id: $("image-project").value || null };
    try {
      const result = await request("/pipelines", { method: "POST", body: JSON.stringify(payload) });
      selectView("overview"); await refreshOverview(); notification("Image job queued (" + result.mode + "). Job ID: " + result.job_id);
    } catch (error) { notification(error.message, true); }
  });
  $("repo-form").addEventListener("submit", async event => {
    event.preventDefault();
    const payload = { kind: "secrets", target: $("repository-url").value.trim(), profile: $("repo-profile").value, project_id: $("repo-project").value || null };
    try {
      const result = await request("/api/security-jobs", { method: "POST", body: JSON.stringify(payload) });
      selectView("overview"); await refreshOverview(); notification("Repository scan queued. Job ID: " + result.job_id);
    } catch (error) { notification(error.message, true); }
  });
  const metabaseUrl = location.protocol + "//" + location.hostname + ":3001/";
  $("metabase-link").href = metabaseUrl;
  $("metabase-button").href = metabaseUrl;
  async function initialize() {
    await refreshHealth();
    try {
      const user = await request("/api/profile");
      showApp(user); selectView("overview");
      await Promise.all([refreshOverview(), loadProjects(), loadCapabilities()]);
    } catch (error) {
      if (error.status === 401) showLogin();
      else { showLogin(); $("login-error").textContent = "Cannot load data: " + error.message; }
    }
  }
  initialize();
  window.setInterval(() => {
    if (!state.user || document.hidden || state.view !== "overview") return;
    refreshOverview().catch(() => {});
    refreshHealth();
  }, 20000);
})();

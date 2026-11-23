/* AppSec Control Center — real API data only; no client-side mocks. */
(() => {
  "use strict";
  const prefix = location.pathname.startsWith("/appsec-api/") ? "/appsec-api" : "";
  const $ = (id) => document.getElementById(id);
  const app = $("app"), loginScreen = $("login-screen"), notice = $("global-notice");
  const state = { user: null, overview: null, view: "overview", result: null, selectedWorkflow: null, workflowState: null, patchEnabled: false };
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
      const info = body && body.error;
      const message = typeof detail === "string" ? detail : "Request failed (" + response.status + ")";
      const suffix = info && info.hint ? " — " + info.hint : "";
      const reference = info && info.request_id ? " [Request: " + info.request_id + "]" : "";
      const error = new Error(message + suffix + reference);
      error.code = info && info.code;
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
    document.querySelector('[data-view="health"]').hidden = user.role !== "admin";
    document.querySelector('[data-view="settings"]').hidden = user.role !== "admin";
    document.querySelector('[data-view="registries"]').hidden = user.role !== "admin";
    document.querySelector('[data-view="users"]').hidden = user.role !== "admin";
    const readOnly = user.role === "viewer";
    document.querySelector('[data-view="scan"]').hidden = readOnly;
    document.querySelector('[data-view="secrets"]').hidden = readOnly;
    if (user.must_change_password) {
      document.querySelectorAll(".nav-item").forEach(n => { n.hidden = n.dataset.view !== "profile"; });
    }
    loginScreen.hidden = true; app.hidden = false;
  }
  function selectView(view) {
    state.view = view;
    document.querySelectorAll(".view").forEach(v => v.hidden = v.id !== "view-" + view);
    document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === view));
    $("breadcrumb").textContent = ({
      overview: "Overview", scan: "New scan", secrets: "Repository scan",
      results: "Results", guided: "My workflows", inventory: "Images & scans",
      approvals: "Approvals", users: "Users & access", registries: "Registries",
      profile: "My profile", settings: "Administration", health: "System health",
      integrations: "Integrations"
    })[view] || "AppSec";
    if (view === "health") refreshSystemHealth().catch(error => notification(error.message, true));
    if (view === "guided") refreshGuided().catch(error => notification(error.message, true));
    if (view === "settings" && state.user?.role === "admin") loadAdminData().catch(error => notification(error.message, true));
    quiet();
    document.dispatchEvent(new CustomEvent("appsec:view", { detail: { view } }));
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
  async function refreshSystemHealth() {
    const data = await request("/api/ui/system/health");
    $("health-database").textContent = data.database;
    const count = (list, status) => (list.find(item => item.status === status) || { count: 0 }).count;
    $("health-queued").textContent = count(data.pipeline_queue, "queued");
    $("health-running").textContent = count(data.pipeline_queue, "running");
    $("health-secret-queued").textContent = count(data.secret_queue, "queued");
    const body = $("heartbeats-body");
    clear(body);
    if (!data.heartbeats.length) empty(body, "No heartbeat received yet. Check worker and scheduler containers.", 4);
    data.heartbeats.forEach(item => {
      const row = node("tr");
      cell(row, item.service);
      cell(row, item.instance);
      cell(row, date(item.last_seen));
      const status = cell(row, "");
      const state = item.seconds_ago <= 120 ? "recent" : "stale / possibly busy";
      status.appendChild(statusPill(state === "recent" ? "success" : "running"));
      status.appendChild(node("span", "small-text", " " + state));
      body.appendChild(row);
    });
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
    state.patchEnabled = Boolean(features.patch_enabled);
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

  function stepItem(container, name, detail, status) {
    const li = node("li", "manual-step " + status);
    const dot = node("span", "step-dot", status === "done" ? "✓" : status === "running" ? "…" : "○");
    const body = node("div");
    body.appendChild(node("strong", "", name));
    body.appendChild(node("p", "muted small-text", detail));
    li.appendChild(dot);
    li.appendChild(body);
    container.appendChild(li);
  }

  async function refreshGuided() {
    const workflows = await request("/api/manual-workflows?limit=80");
    const body = $("guided-list");
    clear(body);
    if (!workflows.length) empty(body, "No manual workflows. Create one from New manual scan.", 5);
    workflows.forEach(w => {
      const row = node("tr");
      cell(row, w.requested_image, "wide-text");
      const c = cell(row, ""); c.appendChild(statusPill(w.state));
      cell(row, w.pipeline_status || "—");
      cell(row, date(w.created_at));
      const act = cell(row, "");
      const label = w.state === "awaiting_approval" ? "Review & decide →" : "Open workflow →";
      act.appendChild(button(label, () => openGuided(w.id)));
      body.appendChild(row);
    });
  }

  async function decideGuided(workflowId, action) {
    if (["approve_patch", "approve_publish"].includes(action) && !state.patchEnabled) {
      notification("Patching is disabled by the administrator. Run ./appsec start --patching after configuring registry credentials.", true);
      return;
    }
    if (action === "approve_patch") {
      const checked = document.getElementById("approval-confirm");
      if (!checked || !checked.checked) return notification("Confirm local patch preparation first.", true);
      if (!window.confirm("Build a local patched image and rescan it? Nothing will be pushed yet.")) return;
    }
    if (action === "approve_publish") {
      const checked = document.getElementById("publish-confirm");
      if (!checked || !checked.checked) return notification("You must explicitly authorize the registry push.", true);
      if (!window.confirm("Final action: push the validated patched image to the registry? This cannot safely be retried automatically.")) return;
    }
    if (action === "cancel" && !window.confirm("Cancel this queued scan?")) return;
    const payload = { action, confirm_patch: action === "approve_patch", confirm_push: action === "approve_publish" };
    try {
      await request("/api/manual-workflows/" + encodeURIComponent(workflowId) + "/decision", {
        method: "POST", body: JSON.stringify(payload)
      });
      await openGuided(workflowId);
      await refreshGuided();
      const messages = {
        approve_patch: "Local patch preparation approved. AppSec will rescan before asking for publication approval.",
        approve_publish: "Registry publication approved and queued. Check the final status before retrying any failure.",
        skip_publish: "Review completed; patched image has NOT been published.",
        finish: "Workflow completed without image modification.",
        cancel: "Queued scan canceled."
      };
      notification(messages[action] || "Decision saved.");
    } catch (error) { notification(error.message, true); }
  }

  async function openGuided(workflowId, silent = false) {
    selectView("guided");
    state.selectedWorkflow = workflowId;
    const root = $("guided-detail");
    if (!silent) root.textContent = "Loading workflow details…";
    try {
      const data = await request("/api/manual-workflows/" + encodeURIComponent(workflowId));
      const w = data.workflow, pipeline = data.pipeline;
      state.workflowState = w.state;
      state.patchEnabled = Boolean(data.patch_enabled);
      clear(root);
      root.appendChild(node("p", "eyebrow", "MANUAL IMAGE WORKFLOW"));
      root.appendChild(node("h2", "", w.requested_image));
      root.appendChild(node("p", "info-note", "Workflow ID: " + w.id + " · Created: " + date(w.created_at)));
      const summary = node("div", "result-stats");
      for (const [title, value] of [["Current state", w.state], ["Policy result", w.policy_status || w.pipeline_status || "Not evaluated"], ["Patch allowed", data.patch_enabled ? "Enabled" : "Disabled"]]) {
        const c = node("div", "mini-stat"); c.appendChild(node("strong", "", value));
        c.appendChild(node("span", "", title)); summary.appendChild(c);
      }
      root.appendChild(summary);
      if (w.state === "awaiting_approval" &&
          ["admin", "operator"].includes(state.user?.role)) {
        const controls = section(root, "Your decision is required");
        controls.appendChild(node("p", "info-note", "Scan complete. Review the findings below, then choose how to finish this workflow."));
        const actionRow = node("div", "approval-actions");
        const finish = node("button", "outline", "✓ Finish without patching");
        finish.type = "button"; finish.addEventListener("click", () => decideGuided(w.id, "finish"));
        actionRow.appendChild(finish);
        if (data.patch_enabled) {
          const warning = node("div", "warning",
            "Registry destination: " + (data.registry_destination || "not configured") +
            ". This step creates a LOCAL patched image only. Registry publication requires a separate approval after the rescan.");
          controls.appendChild(warning);
          const label = node("label", "approval-checkbox");
          const checkbox = document.createElement("input");
          checkbox.type = "checkbox"; checkbox.id = "approval-confirm";
          label.appendChild(checkbox);
          label.appendChild(node("span", "", "I approve building a local patched image for rescanning; no registry Push at this step."));
          controls.appendChild(label);
          const approve = node("button", "primary", "Prepare patch & rescan");
          approve.type = "button"; approve.addEventListener("click", () => decideGuided(w.id, "approve_patch"));
          actionRow.appendChild(approve);
        } else {
          controls.appendChild(node("p", "info-note", "Patching is disabled in this deployment. You can safely finish now; an administrator can enable patching later."));
        }
        controls.appendChild(actionRow);
      }
      const scans = pipeline?.scans || [], artifacts = pipeline?.artifacts || [], patches = pipeline?.patches || [], diffs = pipeline?.diffs || [];
      const orig = scans.find(s => s.phase === "original"), patched = scans.find(s => s.phase === "patched");
      const sbomReady = artifacts.some(a => a.kind === "sbom" && (!orig || a.scan_id === orig.id));
      const sec = section(root, "Step-by-step progress");
      const ol = node("ol", "manual-timeline");
      const scanFailed = w.scan_job_status === "failed";
      stepItem(ol, "1. Queue and scan image", "Trivy inspects the actual image and saves vulnerability findings.", scanFailed ? "failed" : w.scan_job_status === "success" ? "done" : w.scan_job_status === "running" ? "running" : "waiting");
      stepItem(ol, "2. Generate SBOM and evaluate policy", "CycloneDX, severity counts and security rules.", sbomReady && pipeline?.policies?.length ? "done" : scanFailed ? "failed" : w.scan_job_status === "running" ? "running" : "waiting");
      stepItem(ol, "3. Review original findings", "Human approval is needed before local patching.", w.decision ? "done" : w.state === "awaiting_approval" ? "running" : "waiting");
      stepItem(ol, "4. Prepare local patched image", "Copa uses BuildKit but does not push to the registry.", w.decision === "finish" ? "skipped" : w.patch_job_status === "success" ? "done" : w.patch_job_status === "failed" ? "failed" : w.decision === "approve_patch" ? "running" : "waiting");
      stepItem(ol, "5. Rescan & compare", "Trivy scans the local patched image; policy is evaluated before publication.", w.decision === "finish" ? "skipped" : diffs.length > 0 && patched ? "done" : w.decision === "approve_patch" ? "running" : "waiting");
      stepItem(ol, "6. Separate publication approval", "Review the new findings and explicitly approve registry Push, or finish without publishing.", w.publish_decision ? "done" : ["awaiting_publication","publication_blocked"].includes(w.state) ? "running" : w.decision === "finish" ? "skipped" : "waiting");
      stepItem(ol, "7. Publish & final report", "Only a validated, policy-passed image can be published.", ["published","completed","completed_without_publish"].includes(w.state) ? "done" : w.state === "publishing" ? "running" : "waiting");
      sec.appendChild(ol);
      if (orig) {
        const results = section(root, "Initial scan results");
        showMetrics(results, [["Critical", orig.critical_count], ["High", orig.high_count], ["Medium", orig.medium_count], ["Low", orig.low_count]]);
        results.appendChild(button("View CVE table and complete reports →", () => openPipeline(w.pipeline_id)));
      }
      if (diffs.length) {
        const d = diffs[diffs.length - 1];
        const result = section(root, "After approval: vulnerability changes");
        showMetrics(result, [["Fixed", d.fixed_count], ["Remaining", d.remaining_count], ["Introduced", d.introduced_count]]);
        result.appendChild(button("Open final scan results →", () => openPipeline(w.pipeline_id)));
      }
      if (["awaiting_publication", "publication_blocked"].includes(w.state) &&
          ["admin", "operator"].includes(state.user?.role)) {
        const controls = section(root, "Final review: publish or stop");
        const lastPatch = patches[0];
        controls.appendChild(node("p", "info-note",
          "Prepared image: " + (lastPatch?.patched_image_ref || "Unavailable") +
          ". The patched version was scanned locally. No registry push has happened."));
        const actions = node("div", "approval-actions");
        const stop = node("button", "outline", "Finish without publishing");
        stop.type = "button";
        stop.addEventListener("click", () => decideGuided(w.id, "skip_publish"));
        actions.appendChild(stop);
        if (w.state === "awaiting_publication" && data.patch_enabled &&
            data.publication_ready && ["admin", "operator"].includes(state.user?.role)) {
          const warn = node("p", "warning",
            "This is a separate registry write. Publishing is allowed only if the patched image passed policy. Failed pushes require manual reconciliation.");
          controls.appendChild(warn);
          const label = node("label", "approval-checkbox");
          const checkbox = document.createElement("input");
          checkbox.type = "checkbox"; checkbox.id = "publish-confirm";
          label.appendChild(checkbox);
          label.appendChild(node("span", "", "I reviewed the post-patch scan and approve publishing the selected image."));
          controls.appendChild(label);
          const publish = node("button", "danger-button", "Approve registry Push");
          publish.type = "button"; publish.addEventListener("click", () => decideGuided(w.id, "approve_publish"));
          actions.appendChild(publish);
        } else if (w.state === "publication_blocked") {
          controls.appendChild(node("p", "warning",
            w.policy_status === "report_only" ?
              "Publication requires enforced policy to pass. This scan used report-only mode." :
              "Publication blocked because the patched image did not pass the final policy. You can finish without publishing."));
        } else if (!data.publication_ready) {
          controls.appendChild(node("p", "warning",
            "Registry publication is not yet authorized. An admin must register the exact destination hostname and enable Push before you can approve."));
        }
        if (data.requires_second_approver) {
          controls.appendChild(node("p", "info-note",
            "Two-person approval is required: the operator approving publication must differ from the patch reviewer."));
        }
        controls.appendChild(actions);
      }
      if (w.state === "queued" && (state.user?.role === "admin" || state.user?.role === "operator")) {
        const cancel = node("button", "outline", "Cancel queued scan");
        cancel.addEventListener("click", () => decideGuided(w.id, "cancel"));
        root.appendChild(cancel);
      }
      if (["failed", "patch_failed", "publish_failed"].includes(w.state)) {
        const failure = w.publish_error || w.patch_error || w.scan_error;
        root.appendChild(node("p", "warning", "Operation failed: " +
          (failure || "See job diagnostics and ask an administrator for the correlation ID.")));
        if (w.state === "failed" && w.scan_job_status === "failed" &&
            ["admin", "operator"].includes(state.user?.role)) {
          root.appendChild(button("Start a NEW scan-only attempt", async () => {
            if (!window.confirm("This starts a NEW scan-only workflow. No patch or push will be retried. Continue?")) return;
            try {
              const response = await request("/api/manual-workflows", {
                method: "POST",
                body: JSON.stringify({image: w.requested_image, project_id: w.project_id})
              });
              await openGuided(response.id);
              notification("New scan-only job created. The failed workflow was preserved for audit.");
            } catch (error) { notification(error.message, true); }
          }));
        } else {
          root.appendChild(node("p", "info-note",
            "Do not blindly retry a failed patch or registry push. An administrator must reconcile the image and destination first."));
        }
      }
      if (data.diagnostics?.length) {
        const diagnostics = section(root, "What went wrong and how to fix it");
        data.diagnostics.forEach(info => {
          const item = node("div", "diagnostic-item");
          item.appendChild(node("strong", "", info.code + " — " + info.title));
          item.appendChild(node("p", "muted", info.hint));
          diagnostics.appendChild(item);
        });
      }
      if (pipeline?.reports?.length || pipeline?.artifacts?.length) {
        const files = section(root, "Saved reports and SBOM");
        const links = node("div", "results-list");
        for (const r of (pipeline?.reports || [])) {
          const a = node("a", "mini-link", "Report · " + r.format + " ↗");
          a.href = prefix + "/api/reports/" + encodeURIComponent(r.id) + "/download";
          a.target = "_blank"; a.rel = "noopener"; links.appendChild(a);
        }
        for (const r of (pipeline?.artifacts || [])) {
          const a = node("a", "mini-link", r.kind + " · " + r.format + " ↗");
          a.href = prefix + "/api/artifacts/" + encodeURIComponent(r.id) + "/download";
          a.target = "_blank"; a.rel = "noopener"; links.appendChild(a);
        }
        files.appendChild(links);
      }
    } catch (error) {
      if (!silent) root.textContent = error.message;
      notification(error.message, true);
    }
  }

  function replaceOptions(id, rows, placeholder, labelKey = "name") {
    const control = $(id), previous = control.value;
    clear(control);
    if (placeholder) {
      const option = document.createElement("option");
      option.value = ""; option.textContent = placeholder; control.appendChild(option);
    }
    rows.forEach(r => {
      const option = document.createElement("option");
      option.value = r.id; option.textContent = r[labelKey] || r.username || r.id;
      control.appendChild(option);
    });
    if ([...control.options].some(o => o.value === previous)) control.value = previous;
  }

  async function loadAdminData() {
    if (state.user?.role !== "admin") return;
    const [teams, projects, users] = await Promise.all([
      request("/api/teams"), request("/api/projects"), request("/api/users")
    ]);
    replaceOptions("new-project-team", teams, "Select a team");
    replaceOptions("member-team", teams);
    replaceOptions("member-user", users, "Select user", "username");
    replaceOptions("policy-project", projects, "Global default (admin)");
    await loadPolicyRules();
  }

  async function loadPolicyRules() {
    const project = $("policy-project").value;
    const query = project ? "?project_id=" + encodeURIComponent(project) : "";
    const rules = await request("/api/policies/effective" + query);
    if ($("policy-project").value !== project) return;
    $("policy-mode").value = rules.enforce ? "enforce" : "report_only";
    for (const severity of ["critical", "high", "medium", "low"]) {
      $("policy-" + severity).value = rules["max_" + severity];
    }
  }

  $("policy-project").addEventListener("change", () => loadPolicyRules().catch(error => notification(error.message, true)));

  function bindForm(id, buildPayload, endpoint, success) {
    $(id).addEventListener("submit", async event => {
      event.preventDefault();
      try {
        await request(typeof endpoint === "function" ? endpoint() : endpoint, { method: "POST", body: JSON.stringify(buildPayload()) });
        notification(success);
        await loadAdminData();
        await loadProjects();
      } catch (error) { notification(error.message, true); }
    });
  }


  $("user-form").addEventListener("submit", async event => {
    event.preventDefault();
    const payload = {
      username: $("new-username").value.trim(),
      display_name: $("new-displayname").value.trim(),
      role: $("new-user-role").value,
      password: $("new-user-password").value
    };
    try {
      const created = await request("/api/users", { method: "POST", body: JSON.stringify(payload) });
      $("new-user-password").value = "";
      $("new-user-result").textContent = "Created " + created.username +
        ". Temporary password must be changed at first login. API access is NOT issued automatically; an admin can issue a key in Users & access.";
      notification("New user created.");
      await loadAdminData();
    } catch (error) {
      $("new-user-result").textContent = "";
      notification(error.message, true);
    }
  });

  bindForm("team-form", () => ({
    name: $("team-name").value.trim(), description: $("team-description").value.trim() || null
  }), "/api/teams", "Team created.");
  bindForm("project-form", () => ({
    name: $("new-project-name").value.trim(), slug: $("new-project-slug").value.trim(),
    team_id: $("new-project-team").value
  }), "/api/projects", "Project created.");
  bindForm("team-member-form", () => ({
    user_id: $("member-user").value, role: $("member-role").value
  }), () => "/api/teams/" + encodeURIComponent($("member-team").value) + "/members", "Membership added.");
  bindForm("policy-form", () => ({
    name: $("policy-name").value.trim(), project_id: $("policy-project").value || null,
    rules: {
      enforce: $("policy-mode").value === "enforce",
      max_critical: Number($("policy-critical").value),
      max_high: Number($("policy-high").value),
      max_medium: Number($("policy-medium").value),
      max_low: Number($("policy-low").value)
    }
  }), "/api/policies", "Policy saved.");
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault(); $("login-error").textContent = "";
    try {
      const res = await request("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          username: $("username").value,
          password: $("password").value,
          otp: $("login-mfa-block").hidden ? null : $("login-otp").value.trim()
        })
      });
      $("password").value = "";
      $("login-otp").value = "";
      $("login-mfa-block").hidden = true;
      showApp(res.user);
      selectView(res.user.must_change_password ? "profile" : "overview");
      if (!res.user.must_change_password) {
        await refreshOverview(); await loadProjects(); await loadCapabilities();
      }
    } catch (error) {
      if (error.code === "MFA_REQUIRED") {
        $("login-mfa-block").hidden = false;
        $("login-otp").focus();
      }
      $("login-error").textContent = error.message;
    }
  });
  $("logout-button").addEventListener("click", async () => {
    try { await request("/api/auth/logout", { method: "POST" }); } catch (_) { /* session may already be invalid */ }
    showLogin();
  });
  document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => selectView(button.dataset.view)));
  document.addEventListener("appsec:open-workflow", event => openGuided(event.detail.id));
  document.addEventListener("appsec:open-pipeline", event => openPipeline(event.detail.id));
  $("refresh-button").addEventListener("click", async () => { quiet(); try { await refreshOverview(); } catch (e) { notification(e.message, true); } });
  $("health-refresh-button").addEventListener("click", async () => { try { await refreshSystemHealth(); } catch (e) { notification(e.message, true); } });
  $("guided-refresh").addEventListener("click", async () => { try { await refreshGuided(); if (state.selectedWorkflow) await openGuided(state.selectedWorkflow); } catch (e) { notification(e.message, true); } });
  $("image-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (!state.user || state.user.role === "viewer") return notification("Viewer cannot start scans.", true);
    const payload = { image: $("image-reference").value.trim(), project_id: $("image-project").value || null };
    try {
      const result = await request("/api/manual-workflows", { method: "POST", body: JSON.stringify(payload) });
      await openGuided(result.id);
      notification("Your scan is queued. AppSec will wait for your decision before any patch or registry push.");
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
      showApp(user); selectView(user.must_change_password ? "profile" : "overview");
      if (!user.must_change_password) await Promise.all([refreshOverview(), loadProjects(), loadCapabilities()]);
    } catch (error) {
      if (error.status === 401) showLogin();
      else { showLogin(); $("login-error").textContent = "Cannot load data: " + error.message; }
    }
  }
  initialize();
  window.setInterval(() => {
    if (!state.user || document.hidden || state.user.must_change_password) return;
    if (state.view === "overview") {
      refreshOverview().catch(() => {});
      refreshHealth();
    }
    if (state.view === "guided" && state.selectedWorkflow && !["awaiting_approval", "awaiting_publication", "publication_blocked",
      "completed", "completed_without_publish", "published",
      "failed", "patch_failed", "publish_failed", "canceled"].includes(state.workflowState)) {
      openGuided(state.selectedWorkflow, true).catch(() => {});
      refreshGuided().catch(() => {});
    }
  }, 20000);
})();

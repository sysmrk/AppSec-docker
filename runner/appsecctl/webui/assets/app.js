/* AppSec Control Center — real API data only; no client-side mocks. */
(() => {
  "use strict";
  const prefix = location.pathname.startsWith("/appsec-api/") ? "/appsec-api" : "";
  const $ = (id) => document.getElementById(id);
  const app = $("app"), loginScreen = $("login-screen"), notice = $("global-notice");
  const state = { user: null, overview: null, view: "overview", result: null, selectedWorkflow: null, workflowState: null, patchEnabled: false };
  const selectedPipelines = new Set();
  let bulkBusy = false;
  let guidedPage = 1, guidedRows = [], guidedRequest = 0;
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
    stopWatch();
    state.user = null;
    selectedPipelines.clear();
    guidedPage = 1; guidedRows = []; guidedRequest++;
    loginScreen.hidden = false; app.hidden = true;
  }
  function showApp(user) {
    state.user = user;
    $("current-user").textContent = user.username + " · " + user.role;
    document.querySelectorAll(".nav-item").forEach(n => { n.hidden = false; });
    document.querySelectorAll("[data-admin-setting]").forEach(n => { n.hidden = user.role !== "admin"; });
    $("tool-update-count").hidden = true;
    const readOnly = user.role === "viewer";
    document.querySelector('[data-view="scan"]').hidden = readOnly;
    document.querySelector('[data-view="secrets"]').hidden = readOnly;
    if (user.must_change_password) {
      document.querySelectorAll(".nav-item").forEach(n => { n.hidden = n.dataset.view !== "profile"; });
    }
    loginScreen.hidden = true; app.hidden = false;
  }
  const settingViews = new Set(["tools","registries","users","projects","health","integrations","profile"]);
  const adminSettings = new Set(["tools","registries","users","projects","health"]);
  let reportReturnView = "overview";
  function selectView(view) {
    if (state.user?.must_change_password) view = "profile";
    else if (view === "settings") view = state.user?.role === "admin" ? "tools" : "profile";
    if (adminSettings.has(view) && state.user?.role !== "admin") view = "profile";
    if (view === "results" && state.view !== "results") reportReturnView = state.view;
    if (state.view !== view) stopWatch();
    state.view = view;
    const inSettings = settingViews.has(view);
    $("settings-navigation").hidden = !inSettings || Boolean(state.user?.must_change_password);
    document.querySelectorAll(".settings-tabs [data-view]").forEach(n => {
      n.classList.toggle("active", n.dataset.view === view);
      if (n.dataset.view === view) n.setAttribute("aria-current","page");
      else n.removeAttribute("aria-current");
    });
    document.querySelectorAll(".view").forEach(v => v.hidden = v.id !== "view-" + view);
    document.querySelectorAll(".nav-item").forEach(n => {
      const active = n.dataset.view === view || (inSettings && n.dataset.view === "settings") ||
        (view === "results" && n.dataset.view === reportReturnView);
      n.classList.toggle("active", active);
      if (active) n.setAttribute("aria-current","page"); else n.removeAttribute("aria-current");
    });
    $("breadcrumb").textContent = ({
      overview: "Overview", scan: "New scan", secrets: "Repository scan",
      results: "Scan report", guided: "My workflows", inventory: "Images & scans",
      approvals: "Approvals", users: "Settings / Users & access", registries: "Settings / Registries",
      profile: "Settings / My profile", tools: "Settings / Tool updates", projects: "Settings / Projects & policies", health: "Settings / System health",
      integrations: "Settings / Integrations"
    })[view] || "AppSec";
    if(view==="integrations") request("/api/integrations/status").then(d=>{
      $("integration-ai-status").textContent=d.local_ai_enabled?"Local AI configured: "+d.model+" (model connectivity verified on request)":"Local AI disabled";
    }).catch(e=>{$("integration-ai-status").textContent=e.message;});
    if(view==="registries"&&state.user?.role==="admin")loadPackageMirrors().catch(e=>notification(e.message,true));
    if (view === "health") refreshSystemHealth().catch(error => notification(error.message, true));
    if (view === "guided") refreshGuided().catch(error => notification(error.message, true));
    if (view === "projects" && state.user?.role === "admin") loadAdminData().catch(error => notification(error.message, true));
    if (view === "tools" && state.user?.role === "admin") loadToolUpdates().catch(error => notification(error.message, true));
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
  function eligiblePipeline(p) {
    return Boolean(p.pipeline_id && p.bulk_eligible);
  }
  function updateBulkControls() {
    const eligible = guidedRows.filter(eligiblePipeline).map(p=>String(p.pipeline_id));
    for (const id of [...selectedPipelines]) if (!eligible.includes(id)) selectedPipelines.delete(id);
    $("pipeline-selection-count").textContent = selectedPipelines.size + " selected";
    $("guided-pagination").querySelectorAll("button").forEach(b => { if (bulkBusy) b.disabled = true; });
    $("pipeline-export").disabled = bulkBusy || !selectedPipelines.size;
    $("pipeline-delete").hidden = state.user?.role !== "admin";
    $("pipeline-delete").disabled = bulkBusy || !selectedPipelines.size || state.user?.role !== "admin";
    const all = $("pipeline-select-all");
    all.disabled = bulkBusy || !eligible.length;
    all.checked = eligible.length > 0 && eligible.every(id=>selectedPipelines.has(id));
    all.indeterminate = selectedPipelines.size > 0 && !all.checked;
    document.querySelectorAll(".pipeline-checkbox").forEach(box=>{
      box.checked=selectedPipelines.has(box.value);
      box.disabled=bulkBusy || !eligible.includes(box.value);
    });
  }
  $("pipeline-select-all").addEventListener("change",event=>{
    selectedPipelines.clear();
    if (event.target.checked) guidedRows.filter(eligiblePipeline).forEach(p=>selectedPipelines.add(String(p.pipeline_id)));
    updateBulkControls();
  });
  $("pipeline-export").addEventListener("click",async()=>{
    const ids = [...selectedPipelines];
    if (!ids.length || bulkBusy) return;
    bulkBusy=true;updateBulkControls();
    try {
      const result=await fetch(prefix+"/api/ui/pipelines/export",{
        method:"POST",credentials:"same-origin",cache:"no-store",
        headers:{"Content-Type":"application/json","X-Requested-With":"AppSec-Control-Center"},
        body:JSON.stringify({pipeline_ids:ids})
      });
      if(!result.ok) {
        const err=await result.json().catch(()=>({}));
        throw new Error(typeof err.detail==="string"?err.detail:"Export failed ("+result.status+")");
      }
      const url=URL.createObjectURL(await result.blob());
      const link=node("a");link.href=url;
      const disposition = result.headers.get("Content-Disposition") || "";
      const match = disposition.match(/filename="([A-Za-z0-9._-]+)"/i);
      const stamp = new Date().toISOString().replace(/[-:]/g,"").replace(/\.\d+Z$/,"Z");
      link.download=match ? match[1] : "appsec-reports-"+stamp+(ids.length===1?".html":".zip");
      document.body.appendChild(link);link.click();link.remove();
      setTimeout(()=>URL.revokeObjectURL(url),30000);
      notification(ids.length+" report(s) exported.");
    } catch(error){notification(error.message,true);}
    finally {bulkBusy=false;updateBulkControls(); await refreshGuided().catch(error=>notification(error.message,true));}
  });
  $("pipeline-delete").addEventListener("click",async()=>{
    const ids=[...selectedPipelines];
    if (!ids.length || bulkBusy || state.user?.role!=="admin") return;
    if(window.prompt("Permanently delete "+ids.length+" selected image workflow(s), DB history and report evidence?\nPending approvals for selected workflows will be discarded. Published registry images and audit records stay.\nType DELETE to confirm:")!=="DELETE")return;
    bulkBusy=true;updateBulkControls();
    const failed=[];let deleted=0,queued=0;
    try {
      for(const id of ids){
        try{
          const result=await request("/api/pipelines/"+encodeURIComponent(id)+"/history?confirm="+encodeURIComponent(id),{method:"DELETE"});
          selectedPipelines.delete(id);deleted++;queued+=Number(result.local_tags_queued_for_removal||0);
        }catch(error){failed.push(id+": "+error.message);}
      }
      state.selectedWorkflow = null; state.workflowState = null;
      $("guided-detail").textContent = "Select a workflow to see progress, results and approval controls.";
      await refreshGuided();
      await refreshOverview();
      notification(deleted+" deleted; "+queued+" local patched tags queued for cleanup."+
        (failed.length?" Failed: "+failed.join("; "):""),failed.length>0);
    }catch(error){notification("Deleted "+deleted+"; refresh failed: "+error.message,true);}
    finally{bulkBusy=false;updateBulkControls(); await refreshGuided().catch(error=>notification(error.message,true));}
  });
  async function refreshOverview() {
    const [data, history] = await Promise.all([
      request("/api/ui/overview"), request("/api/ui/image-workflows?limit=10&page=1")
    ]);
    state.overview = data;
    for (const [id, key] of [["stat-total", "total"], ["stat-passed", "passed"], ["stat-policy", "policy_failed"], ["stat-failed", "failed"]]) {
      $(id).textContent = text(data.summary[key] ?? 0);
    }
    const pipelines = $("pipelines-body"); clear(pipelines);
    if (!history.items.length) empty(pipelines, "No image workflows yet. Start your first real scan.", 6);
    history.items.forEach(w => {
      const r = node("tr");
      cell(r, w.requested_image, "wide-text");
      cell(r, "").appendChild(statusPill(w.state));
      cell(r, w.critical_count); cell(r, w.high_count);
      cell(r, date(w.created_at));
      appendWorkflowAction(cell(r, ""), w);
      pipelines.appendChild(r);
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
    if(state.user?.role === "admin") loadToolUpdates().catch(() => {});
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
      holder.appendChild(node("p", "info-note", "Showing up to 200 findings. Full unified HTML export includes every in-scope finding. UNKNOWN requires triage; LOW is raw evidence only."));
    } catch (error) { holder.textContent = error.message; }
  }

  /* One data-driven panel for both Results and My Workflows. No fabricated scan totals. */
  function renderOptimizedSummary(root, d) {
    const run=d?.optimization, r=run?.result;
    if(run?.state!=="completed"||r?.comparison!=="frozen_db")return false;
    const block=section(root,"Final result · Original vs optimized image");
    block.classList.add("unified-summary");
    const before=r.original_severity||(run.stage==="original"?r.base_severity:null);
    const after=r.candidate_severity||{};
    // Both cards use the persisted frozen-DB comparison, not the earlier
    // initial scan or a synthetic Copa scan. Preserve unknown counts as unknown.
    const original=[...(d?.scans||[])].reverse().find(s=>s.phase==="original");
    const phases=node("div","scan-phases");
    for(const [i,label,count,ref,id] of [
      [0,"01 · INITIAL SCAN",r.original_findings,original?.image_ref,r.image_ids?.[0]],
      [1,"02 · FINAL OPTIMIZED SCAN",r.overall_findings,r.candidate,r.candidate_image_id]
    ]){
      const card=node("article","scan-phase-card "+(i?"phase-after":"phase-before"));
      card.appendChild(node("span","phase-label",label));
      card.appendChild(node("strong","phase-count",count));
      card.appendChild(node("small","","Frozen DB rescan · all severities, including LOW"));
      if(ref)card.appendChild(node("p","small-text wide-text","Image: "+ref));
      if(id)card.appendChild(node("p","small-text wide-text","Image ID: "+id));
      if(run.updated_at)card.appendChild(node("p","small-text","Comparison recorded: "+date(run.updated_at)));
      phases.appendChild(card);
    }
    block.appendChild(phases);
    showMetrics(block,[["Net reduction",r.original_findings!=null&&r.overall_findings!=null?r.original_findings-r.overall_findings:null],
      ["Introduced",r.overall_introduced]]);
    if(!(d?.patches||[]).length&&!(d?.scans||[]).some(s=>s.phase==="patched")){
      block.appendChild(node("p","info-note","No separate Copa patch or rescan was recorded. The final card shows the verified optimized image, not a Copa result."));
    }
    const rows=node("div","severity-graph"), palette={CRITICAL:"#d74466",HIGH:"#ec8c43",MEDIUM:"#d6aa38",LOW:"#2aa88a",UNKNOWN:"#8894a8"};
    const keys=Object.keys(palette);
    const max=Math.max(1,...keys.flatMap(k=>[Number(before?.[k]||0),Number(after[k]||0)]));
    for(const k of keys){
      const row=node("div","severity-graph-row"),chart=node("div","severity-chart"),values=node("div","severity-values");
      row.appendChild(node("strong","severity-name",k));
      for(const [phase,n] of [["before",before?.[k]],["after",after[k]]]){
        const lane=node("div","severity-track"),bar=node("div","severity-fill "+phase);
        bar.style.width=(n?Math.max(2,n/max*100):0)+"%";bar.style.backgroundColor=palette[k];lane.appendChild(bar);chart.appendChild(lane);
      }
      values.appendChild(node("strong","",text(before?.[k])));values.appendChild(node("span","","→"));values.appendChild(node("strong","",text(after[k])));
      row.appendChild(chart);row.appendChild(values);rows.appendChild(row);
    }
    block.appendChild(node("p","info-note","Top: original · bottom: optimized candidate. Both scanned using the same frozen Trivy database. All severities included."));
    block.appendChild(rows);
    block.appendChild(node("p","wide-text","Final local image: "+text(r.candidate)+" · "+text(r.candidate_image_id)));
    block.appendChild(node("p","info-note","Security comparison blockers: "+((r.comparison_blockers||[]).join(", ")||"None recorded")+". Functional tests not verified; registry publication not authorized."));
    const html=d?.reports?.find(x=>x.format==="html");
    if(html){const a=node("a","primary report-main-link","Open consolidated report ↗");a.href=prefix+"/api/reports/"+encodeURIComponent(html.id)+"/download";a.target="_blank";a.rel="noopener";block.appendChild(a);}
    return true;
  }

  function renderUnifiedSummary(root, d) {
    const scans = d?.scans || [];
    for(const scan of scans){
      const meta=scan.evidence?.trivy_db;
      if(meta?.fresh===false)root.appendChild(node("p","info-note","WARNING: "+scan.phase+" scan used overdue Trivy DB ("+text(meta.age_hours)+" hours old; updated "+text(meta.updated_at)+"). Automatic publication blocked."));
    }
    const optimized=renderOptimizedSummary(root,d);
    const originalRecord = [...scans].reverse().find(s => s.phase === "original");
    const finalRecord = [...scans].reverse().find(s => s.phase === "patched");
    // Completed optimization is the final result. Do not render a duplicate
    // empty Copa comparison if there is no actual Copa attempt or scan.
    if(optimized&&!finalRecord&&!(d?.patches||[]).length)return;
    const old = originalRecord?.status === "success" ? originalRecord : null;
    const after = finalRecord?.status === "success" ? finalRecord : null;
    const verified = Boolean(old?.evidence?.verified && after?.evidence?.verified &&
      old.evidence.image_id !== after.evidence.image_id && old.evidence.scope === after.evidence.scope);
    const diff = verified ? d?.diffs?.find(x=>String(x.original_scan_id)===String(old.id)&&String(x.patched_scan_id)===String(after.id)) : null;
    const recommendation = verified && diff ? d?.policies?.find(p=>String(p.scan_id)===String(after.id)&&["recommended","not_recommended"].includes(p.status)) : null;
    let parent=root;
    if(optimized){
      parent=node("details","advanced-evidence");
      parent.appendChild(node("summary","","Intermediate Copa evidence (optional)"));
      root.appendChild(parent);
    }
    const block = section(parent, optimized?"Copa patch evidence (separate from optimized candidate)":"Initial scan vs post-fix scan");
    block.classList.add("unified-summary");
    const phases = node("div", "scan-phases");
    [["01 · INITIAL SCAN", old], ["02 · AFTER PATCH", after]].forEach(([name, scan], i) => {
      const card = node("article", "scan-phase-card " + (i ? "phase-after" : "phase-before"));
      card.appendChild(node("span", "phase-label", name));
      card.appendChild(node("strong", "phase-count",
        scan ? ["critical_count", "high_count", "medium_count", "unknown_count"].reduce((n,k)=>n+Number(scan[k]||0),0) : "—"));
      const record=i?finalRecord:originalRecord;
      card.appendChild(node("small", "", scan ? (scan.evidence?.verified ? "OS + application CVEs · LOW excluded" : "Legacy scan · scope/identity not verified") :
        record?.status === "failed" ? "Scan failed · results unavailable" :
        record?.status === "running" ? "Scan running · results pending" : "Not scanned yet · no result available"));
      if (scan) {
        card.appendChild(node("p","small-text wide-text", "Image: "+scan.image_ref));
        card.appendChild(node("p","small-text wide-text", "Image ID: "+(scan.evidence?.image_id||"not recorded")));
        card.appendChild(node("p","small-text", "Scan: "+scan.id+" · "+date(scan.finished_at)));
        if (scan.evidence?.verified) card.appendChild(node("p","small-text",
          "Packages inspected: OS "+text(scan.evidence.os_package_count)+" · Application "+text(scan.evidence.application_package_count)));
      }
      phases.appendChild(card);
    });
    block.appendChild(phases);
    const rows = node("div", "severity-graph"), palette = {
      CRITICAL: "#d74466", HIGH: "#ec8c43", MEDIUM: "#d6aa38", LOW: "#2aa88a", UNKNOWN: "#8894a8"
    };
    const sev = [["CRITICAL","critical_count"],["HIGH","high_count"],["MEDIUM","medium_count"],["UNKNOWN","unknown_count"]];
    const scale = Math.max(1, ...sev.flatMap(([,key])=>[Number(old?.[key]||0),Number(after?.[key]||0)]));
    for (const [name, key] of sev) {
      const wrap = node("div", "severity-graph-row"), values = node("div", "severity-values");
      const chart = node("div", "severity-chart");
      wrap.appendChild(node("strong", "severity-name", name));
      for (const [phase,scan] of [["before",old],["after",after]]) {
        const lane=node("div","severity-track"),bar=node("div","severity-fill "+phase);
        const n=Number(scan?.[key]||0);
        bar.style.width=(n?Math.max(2,n/scale*100):0)+"%";
        bar.style.backgroundColor=palette[name];
        lane.appendChild(bar);chart.appendChild(lane);
      }
      values.appendChild(node("strong","",old?String(old[key]||0):"—"));
      values.appendChild(node("span","","→"));
      values.appendChild(node("strong","",after?String(after[key]||0):"—"));
      wrap.appendChild(chart);wrap.appendChild(values);rows.appendChild(wrap);
    }
    block.appendChild(node("p","info-note","Top bar: original scan · Bottom bar: post-patch scan. Same scale for all severities."));
    block.appendChild(rows);
    if (diff) {
      const changes=node("div","change-metrics");
      for (const [label,count,kind] of [["No longer detected",diff.report_fixed_count ?? diff.fixed_count,"fixed"],["Remaining",diff.report_remaining_count ?? diff.remaining_count,"remaining"],["Introduced",diff.report_introduced_count ?? diff.introduced_count,"introduced"]]) {
        const item=node("article","change-metric "+kind);
        item.appendChild(node("strong","",count));item.appendChild(node("span","",label));changes.appendChild(item);
      }
      block.appendChild(changes);
    } else {
      block.appendChild(node("p","info-note",optimized?"No separate Copa rescan was recorded. The final optimized comparison is shown above.":"No post-fix comparison yet. This remains pending until an actual patched rescan completes."));
    }
    const advisory=node("div","recommend-banner "+
      (recommendation?.status==="recommended"?"good":recommendation?.status==="not_recommended"?"caution":"pending"));
    const words=recommendation?.status==="recommended"?"Recommended":
      recommendation?.status==="not_recommended"?"Not recommended":"Recommendation pending";
    advisory.appendChild(node("strong","",words));
    advisory.appendChild(node("p","",recommendation?
      "Based only on post-fix scan findings. Advisory thresholds do not fail or pass the workflow.":
      "Policy is evaluated only after the patched rescan, not at the initial scan."));
    if (recommendation?.violations?.length) {
      const reasons=node("ul");
      recommendation.violations.forEach(v=>reasons.appendChild(node("li","",
        v.severity+": "+v.count+" found; recommended maximum "+v.limit)));
      advisory.appendChild(reasons);
    }
    block.appendChild(advisory);
    const publication = d?.patches?.[0];
    if (publication) {
      const section = node("div","detail-section");
      section.appendChild(node("h2","","Image publication"));
      section.appendChild(node("p","wide-text","Local image: "+text(publication.local_image_ref)));
      section.appendChild(node("p","","Status: "+text(publication.publication_status)));
      if(publication.strategy)section.appendChild(node("p","","Copa strategy: "+publication.strategy));
      if(publication.package_mirror)section.appendChild(node("p","","Package mirror: "+publication.package_mirror));
      if (publication.publication_status==="published") {
        section.appendChild(node("p","wide-text","Published image: "+text(publication.patched_image_ref)));
        section.appendChild(node("p","wide-text","Registry digest: "+text(publication.published_digest)));
        section.appendChild(node("p","","Published at: "+date(publication.published_at)));
      }
      block.appendChild(section);
    }
    const html = d?.reports?.find(x=>x.format==="html");
    if (html) {
      const a=node("a","primary report-main-link","Open single visual report ↗");
      a.href=prefix+"/api/reports/"+encodeURIComponent(html.id)+"/download";
      a.target="_blank";a.rel="noopener";block.appendChild(a);
    }
  }

  async function openPipeline(id) {
    selectView("results");
    const root=$("result-detail");root.textContent="Loading consolidated report…";
    try {
      const d=await request("/api/ui/pipelines/"+encodeURIComponent(id));
      clear(root);root.className="panel result-panel";
      const top=node("div","result-header"), left=node("div");
      left.appendChild(node("p","eyebrow","IMAGE SECURITY · ONE REPORT"));
      left.appendChild(node("h2","",d.pipeline.requested_image));
      left.appendChild(node("p","info-note","Pipeline "+d.pipeline.id));
      top.appendChild(left);top.appendChild(statusPill(d.pipeline.status));root.appendChild(top);
      renderUnifiedSummary(root,d);
      if (d.pipeline.error_message) {
        const p=section(root,"Execution error");
        p.appendChild(node("p","warning",d.pipeline.error_message));
      }
      if (d.scans.length) {
        const evidence=node("details","advanced-evidence"),caption=node("summary","","Browse individual CVEs (advanced)");
        evidence.appendChild(caption);
        const filters=node("div","filters"),selector=node("select","result-filter"),severity=node("select","result-filter");
        d.scans.forEach(item=>{
          const option=node("option","",item.phase+" · "+item.status);
          option.value=String(item.id);selector.appendChild(option);
        });
        const last=d.scans.find(x=>x.phase==="patched")||d.scans[0];
        selector.value=String(last.id);
        ["All report severities","CRITICAL","HIGH","MEDIUM","UNKNOWN","LOW"].forEach((name,i)=>{
          const o=node("option","",name);o.value=i?name:"";severity.appendChild(o);
        });
        filters.appendChild(selector);filters.appendChild(severity);evidence.appendChild(filters);
        const table=node("div");table.id="finding-table";evidence.appendChild(table);
        root.appendChild(evidence);
        const load=()=>loadVulnerabilities(selector.value,severity.value);
        selector.addEventListener("change",load);severity.addEventListener("change",load);
        evidence.addEventListener("toggle",()=>{if(evidence.open&&table.childNodes.length===0)load();});
      }
      const advanced=node("details","advanced-evidence");
      advanced.appendChild(node("summary","","Raw evidence & SBOM (advanced downloads)"));
      const links=node("div","results-list");
      d.artifacts.forEach(a=>{
        const link=node("a","mini-link",a.kind+" · "+a.format+" ↗");
        link.href=prefix+"/api/artifacts/"+encodeURIComponent(a.id)+"/download";
        link.target="_blank";link.rel="noopener";links.appendChild(link);
      });
      advanced.appendChild(links.childNodes.length?links:node("p","info-note","No artifacts available"));
      root.appendChild(advanced);
      if(state.user?.role==="admin") {
        const danger=node("div","history-danger");
        danger.appendChild(node("p","info-note","Remove this finished pipeline and its stored evidence permanently."));
        const remove=node("button","outline small","Delete this pipeline history");
        remove.addEventListener("click",()=>deletePipelineHistory(d.pipeline.id));
        danger.appendChild(remove);root.appendChild(danger);
      }
    }catch(error){root.textContent=error.message;notification(error.message,true);}
  }

  async function deletePipelineHistory(id) {
    const value=window.prompt("Permanent deletion (database, scans, report files and object storage).\nType DELETE to confirm:");
    if(value!=="DELETE")return;
    try{
      const result=await request("/api/pipelines/"+encodeURIComponent(id)+"/history?confirm="+encodeURIComponent(id),{method:"DELETE"});
      notification("Pipeline DB history and evidence removed. "+
        (result.local_tags_queued_for_removal ? result.local_tags_queued_for_removal+" local patched Docker tag(s) queued for Worker cleanup." : "No local tags to remove.")+
        " Published images in remote registries are preserved.");
      $("result-detail").textContent="History deleted. No report is available.";
      await refreshGuided();await refreshOverview();
    }catch(error){notification(error.message,true);}
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
      attachWatch(root,"/api/security-jobs/"+encodeURIComponent(id)+"/watch");
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
    const dot = node("span", "step-dot", status === "done" ? "✓" : status === "running" ? "…" : status === "skipped" ? "—" : status === "failed" ? "!" : "○");
    const body = node("div");
    body.appendChild(node("strong", "", name+(status==="skipped"?" · Skipped":"")));
    body.appendChild(node("p", "muted small-text", detail));
    li.appendChild(dot);
    li.appendChild(body);
    container.appendChild(li);
  }

  function appendWorkflowAction(act, w) {
    if (w.kind === "manual") {
      const label = w.state === "awaiting_approval" ? "Review & decide →" : "Open workflow →";
      act.appendChild(button(label, () => openGuided(w.id)));
    } else if (w.pipeline_id) {
      act.appendChild(button("Results →", () => openPipeline(w.pipeline_id)));
    }
  }

  async function refreshGuided(page = guidedPage) {
    const token = ++guidedRequest;
    const history = await request("/api/ui/image-workflows?limit=20&page=" + encodeURIComponent(page));
    if (token !== guidedRequest) return;
    if (guidedPage !== history.page) selectedPipelines.clear();
    guidedPage = history.page;
    guidedRows = history.items;
    const body = $("guided-list");
    clear(body);
    if (!guidedRows.length) empty(body, "No image workflows. Create one from New manual scan.", 6);
    guidedRows.forEach(w => {
      const row = node("tr");
      const choose = cell(row, "");
      const checkbox = node("input", "pipeline-checkbox");
      checkbox.type = "checkbox";
      checkbox.value = String(w.pipeline_id || "");
      checkbox.setAttribute("aria-label", "Select " + w.requested_image);
      if (!eligiblePipeline(w)) {
        const reason = w.bulk_disabled_reason || "Workflow is not ready for bulk actions.";
        checkbox.title = reason;
        choose.title = reason;
        choose.appendChild(node("span", "small-text muted", " · " + reason));
      }
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) selectedPipelines.add(checkbox.value);
        else selectedPipelines.delete(checkbox.value);
        updateBulkControls();
      });
      choose.appendChild(checkbox);
      cell(row, w.requested_image, "wide-text");
      cell(row, "").appendChild(statusPill(w.state));
      cell(row, w.policy_status || "Pending post-patch");
      cell(row, date(w.created_at));
      appendWorkflowAction(cell(row, ""), w);
      body.appendChild(row);
    });
    const pager = $("guided-pagination"); clear(pager);
    if (history.total_pages > 1) {
      const go = n => refreshGuided(n).catch(error => notification(error.message, true));
      const addPage = (label, number, disabled = false) => {
        const b = button(label, () => go(number));
        b.className = "outline small";
        b.disabled = disabled || bulkBusy;
        if (number === guidedPage && label === String(number)) b.setAttribute("aria-current", "page");
        pager.appendChild(b);
      };
      addPage("Previous", guidedPage - 1, guidedPage === 1);
      const pages = [...new Set([1, ...Array.from({length: 5}, (_, i) => guidedPage + i - 2), history.total_pages])]
        .filter(n => n >= 1 && n <= history.total_pages).sort((a,b)=>a-b);
      let last = 0;
      for (const number of pages) {
        if (last && number > last + 1) pager.appendChild(node("span", "muted", "…"));
        addPage(String(number), number, number === guidedPage);
        last = number;
      }
      addPage("Next", guidedPage + 1, guidedPage === history.total_pages);
    }
    pager.appendChild(node("span", "muted", history.total + " workflow(s) · Page " + guidedPage + " of " + history.total_pages));
    updateBulkControls();
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
    const payload = { action, confirm_patch: action === "approve_patch", confirm_push: action === "approve_publish",
      destination: action === "approve_publish" ? $("publish-destination")?.value?.trim() : null };
    if (action === "approve_publish") { const reason=window.prompt("Risk acceptance / publication reason (required when not recommended):"); if(reason===null)return; payload.risk_reason=reason.trim(); }
    try {
      await request("/api/manual-workflows/" + encodeURIComponent(workflowId) + "/decision", {
        method: "POST", body: JSON.stringify(payload)
      });
      await openGuided(workflowId);
      await refreshGuided();
      const messages = {
        approve_patch: "Local patch preparation approved. AppSec will rescan before asking for publication approval.",
        approve_publish: "Registry publication approved and queued. Check the final status before retrying any failure.",
        skip_publish: "Patched image kept in your local Docker engine; no registry push was performed.",
        finish: "Workflow completed without image modification.",
        cancel: "Queued scan canceled."
      };
      notification(messages[action] || "Decision saved.");
    } catch (error) { notification(error.message, true); }
  }

  let watchSession = null;
  function stopWatch() {
    if (watchSession) { clearTimeout(watchSession.timer); watchSession = null; }
  }
  function attachWatch(root, path) {
    let current = watchSession;
    if (!current || current.path !== path) {
      stopWatch();
      current = {path, cursor:0, lines:[], timer:null, busy:false, state:"Connecting", follow:true};
      watchSession = current;
    }
    const box=section(root,"Live execution watch");
    const status=node("p","info-note",current.state);
    const terminal=node("pre","job-terminal",current.lines.join("\n") || "Waiting for recorded worker events…");
    terminal.tabIndex=0;
    box.appendChild(status);
    const controls=node("div","approval-actions");
    const followButton=node("button","outline",current.follow?"Pause auto-scroll":"Resume auto-scroll");
    followButton.type="button";followButton.addEventListener("click",()=>{
      current.follow=!current.follow;
      followButton.textContent=current.follow?"Pause auto-scroll":"Resume auto-scroll";
      if(current.follow)terminal.scrollTop=terminal.scrollHeight;
    });
    const copyButton=node("button","outline","Copy watch log");copyButton.type="button";
    copyButton.addEventListener("click",async()=>{
      try{await navigator.clipboard.writeText(current.lines.join("\n"));notification("Watch log copied");}
      catch(e){notification("Clipboard unavailable; select and copy the terminal text.",true);}
    });
    controls.appendChild(followButton);controls.appendChild(copyButton);box.appendChild(controls);
    box.appendChild(terminal);
    box.appendChild(node("p","hint","Actual worker/tool events, refreshed every 2 seconds. Raw secret-bearing output and shell input are intentionally unavailable."));
    current.status=status;current.terminal=terminal;
    terminal.scrollTop=terminal.scrollHeight;
    async function poll() {
      if (watchSession!==current || current.busy) return;
      current.busy=true;
      try {
        const result=await request(path+"?after="+current.cursor);
        if (watchSession!==current) return;
        for (const e of result.events) current.lines.push(date(e.created_at)+"  "+e.detail);
        current.lines=current.lines.slice(-1000);
        current.cursor=result.next_cursor;
        current.state="Workflow/job: "+result.state+(result.optimization_state?" · "+result.optimization_operation+": "+result.optimization_state:"")+" · connected";
        const follow=current.terminal.scrollHeight-current.terminal.scrollTop-current.terminal.clientHeight<40;
        current.terminal.textContent=current.lines.join("\n") || "No recorded events yet.";
        current.status.textContent=current.state;
        if(current.follow && follow) current.terminal.scrollTop=current.terminal.scrollHeight;
        if(state.view==="guided" && path==="/api/manual-workflows/"+encodeURIComponent(state.selectedWorkflow)+"/watch") {
          const changed=result.state!==state.workflowState || (result.optimization_state||null)!==state.optimizationState;
          if(changed && !current.refreshing) {
            current.refreshing=true;
            try { await openGuided(state.selectedWorkflow,true); }
            finally { current.refreshing=false; }
          }
        }
      } catch(e) {
        if (watchSession!==current) return;
        current.status.textContent="Watch unavailable: "+e.message;
        if(e.status===401 || e.status===403 || e.status===404) { stopWatch(); return; }
      } finally {
        current.busy=false;
        if(watchSession===current) current.timer=setTimeout(poll,document.hidden?15000:2000);
      }
    }
    if (!current.busy) {clearTimeout(current.timer);poll();}
  }

  function optimizationPanel(root,w) {
    const panel=node("details","panel");
    panel.open=Boolean(w.optimization_active)||w.execution_mode==="auto_optimize";
    panel.appendChild(node("summary","",w.unattended?"Automatic optimization results":"Optimization results and approval"));
    root.appendChild(panel);
    const body=node("div");panel.appendChild(body);
    const path="/api/manual-workflows/"+encodeURIComponent(w.id)+"/optimization";
    const refresh=node("button","outline","Refresh optimization");refresh.type="button";panel.appendChild(refresh);
    let busy=false,refreshActive=false;
    async function load() {
      if(busy||!panel.open)return;
      busy=true;
      try {
        const data=await request(path);
        if(!body.isConnected)return;
        clear(body);
        body.appendChild(node("p","info-note",data.enabled?"Explicit local-only optimization. Never publishes or replaces the existing patch.":"Optimization worker disabled; enable only in an isolated lab."));
        const admin=state.user?.role==="admin";
        const active=data.runs.some(r=>["queued","planning","awaiting_approval","build_queued","building"].includes(r.state));
        refreshActive=data.runs.some(r=>["queued","planning","build_queued","building"].includes(r.state));
        if(admin && data.enabled && !w.unattended && !active && ["awaiting_approval","awaiting_publication","completed","completed_without_publish","published","publication_blocked"].includes(w.state)) {
          const advanced=node("details");advanced.appendChild(node("summary","","Advanced package diagnostics (optional)"));
          advanced.appendChild(node("p","hint","Repository check finds available updates; inventory compares scanner and dpkg; native upgrade builds an alternative candidate without deliberate package removal."));
          const form=node("div","approval-actions");
          const stage=node("select");
          for(const s of ["original","residual"]) {const o=node("option","",s==="original"?"Original scan":"After Copa patch");o.value=s;stage.appendChild(o);}
          if(w.patch_job_status==="success")stage.value="residual";
          const modules=[];
          for(const name of data.modules) {
            const label=node("label","approval-checkbox"),check=node("input");check.type="checkbox";check.value=name;
            label.appendChild(check);label.appendChild(node("span","",name));advanced.appendChild(label);modules.push(check);
          }
          form.appendChild(stage);
          for(const [operation,title] of [["availability","Check package repository"],["inventory","Reconcile inventory"],["upgrade","Plan native APT upgrade"]]) {
            const b=node("button","outline",title);b.type="button";b.addEventListener("click",async()=>{
              b.disabled=true;
              try {
                await request(path,{method:"POST",body:JSON.stringify({operation,stage:stage.value,roots:operation==="debloat"?modules.filter(m=>m.checked).map(m=>m.value):[]})});
                await load();
              } catch(e) {notification(e.message,true);b.disabled=false;}
            });form.appendChild(b);
          }
          advanced.appendChild(form);body.appendChild(advanced);
        }
        for(const run of data.runs) {
          const card=node("div","panel");
          const titles={debloat:"Remove unused modules",upgrade:"Upgrade installed OS packages",inventory:"Verify package inventory",availability:"Check signed package repositories"};
          const descriptions={queued:"Queued — the worker will start automatically.",planning:"Analyzing package dependencies and evidence.",awaiting_approval:"Next: review the exact package list and approve the local build.",build_queued:"Approved; waiting for the worker.",building:"Building and rescanning the candidate.",completed:"Finished. Review the candidate results.",failed:"Failed. Review the diagnostic.",canceled:"Canceled; existing evidence retained."};
          card.appendChild(node("h3","",titles[run.operation]||run.operation));
          card.appendChild(node("p","info-note",descriptions[run.state]||run.state));
          if(run.error_code)card.appendChild(node("p","warning","Task failed: "+run.error_code+"; inspect worker diagnostics."));
          if(run.plan) {
            const removing=Array.isArray(run.plan.remove);
            const items=removing?run.plan.remove:Object.entries(run.plan.updates||{}).map(([p,v])=>p+"  "+v.before+" → "+v.after);
            card.appendChild(node("p","info-note",removing?"Estimated findings: "+run.plan.estimated_findings+" · Packages to remove: "+items.length:"Exact package upgrades: "+items.length+" · Mirror: "+run.plan.mirror));
            const details=node("details");details.appendChild(node("summary","",removing?"Review exact removal closure":"Review exact upgrade versions"));details.appendChild(node("pre","job-terminal",items.join("\n")));card.appendChild(details);
            if(admin&&run.state==="awaiting_approval") {
              const label=node("label","approval-checkbox"),check=node("input");check.type="checkbox";
              label.appendChild(check);label.appendChild(node("span","",removing?"I reviewed every package and accept loss of these optional capabilities.":"I reviewed the exact signed repository package upgrades and approve a local candidate."));card.appendChild(label);
              const b=node("button","primary","Approve local build & rescan");b.type="button";b.disabled=true;
              check.addEventListener("change",()=>{b.disabled=!check.checked;});
              b.addEventListener("click",async()=>{b.disabled=true;try{await request(path+"/"+run.id+"/decision",{method:"POST",body:JSON.stringify({action:"approve",plan_sha256:run.plan.plan_sha256})});await load();}catch(e){notification(e.message,true);b.disabled=false;}});
              card.appendChild(b);
            }
          }
          if(admin&&["queued","awaiting_approval","build_queued"].includes(run.state)){
            const cancel=node("button","outline","Cancel task");cancel.type="button";cancel.addEventListener("click",async()=>{try{await request(path+"/"+run.id+"/decision",{method:"POST",body:JSON.stringify({action:"cancel"})});await load();}catch(e){notification(e.message,true);}});card.appendChild(cancel);
          }
          if(run.result) {
            const detail=node("details");detail.appendChild(node("summary","","Result evidence"));detail.appendChild(node("pre","job-terminal",JSON.stringify(run.result,null,2)));card.appendChild(detail);
            if(run.result.candidate)card.appendChild(node("p","warning","Local candidate: "+run.result.candidate+" · functional validation and publication not authorized."));
            if(run.result.candidate_findings!=null)showMetrics(card,[["Base findings",run.result.base_findings],["Candidate findings",run.result.candidate_findings],["Introduced",run.result.introduced]]);
          }
          body.appendChild(card);
        }
      }catch(e){body.textContent=e.message;}finally{busy=false;}
    }
    refresh.addEventListener("click",load);
    panel.addEventListener("toggle",()=>{if(panel.open)load();});
    if(panel.open)load();
    const timer=setInterval(()=>{if(!panel.isConnected){clearInterval(timer);return;} if(panel.open&&!document.hidden&&state.view==="guided"&&refreshActive)load();},5000);
  }

  async function openGuided(workflowId, silent = false) {
    selectView("guided");
    state.selectedWorkflow = workflowId;
    const root = $("guided-detail");
    if (!silent) root.textContent = "Loading workflow details…";
    try {
      const data = await request("/api/manual-workflows/" + encodeURIComponent(workflowId));
      if(state.selectedWorkflow!==workflowId || state.view!=="guided")return;
      const w = data.workflow, pipeline = data.pipeline;
      state.workflowState = w.state;
      state.optimizationActive=Boolean(w.optimization_active);
      state.optimizationState=w.optimization_state||null;
      state.patchEnabled = Boolean(data.patch_enabled);
      clear(root);
      root.appendChild(node("p", "eyebrow", "MANUAL IMAGE WORKFLOW"));
      root.appendChild(node("h2", "", w.requested_image));
      root.appendChild(node("p", "info-note", "Workflow ID: " + w.id + " · Created: " + date(w.created_at)));
      const summary = node("div", "result-stats");
      for (const [title, value] of [["Current state", w.state], ["Post-fix recommendation", w.policy_status || "Pending rescan"], ["Patch mode", data.patch_enabled ? "Enabled" : "Disabled"]]) {
        const c = node("div", "mini-stat"); c.appendChild(node("strong", "", value));
        c.appendChild(node("span", "", title)); summary.appendChild(c);
      }
      root.appendChild(summary);
      attachWatch(root,"/api/manual-workflows/"+encodeURIComponent(w.id)+"/watch");
      root.appendChild(node("p","info-note","Selected route: "+(w.execution_mode||"guided").replaceAll("_"," ")));
      if(w.auto_error)root.appendChild(node("p","warning",w.auto_error));
      if(w.unattended)root.appendChild(node("p","info-note","Automatic route: no additional decisions. Output: "+(w.auto_destination||"local image / report only")));
      if(["admin","operator"].includes(state.user?.role)&&!["stopped","stopping","publishing","published","completed","completed_without_publish","failed","patch_failed","publish_failed","canceled"].includes(w.state)){
        const stop=node("button","danger-button","Stop workflow");stop.type="button";
        stop.addEventListener("click",async()=>{
          if(!window.confirm("Stop future stages and retries? The current tool operation may finish at a safe boundary. Local images and reports are retained."))return;
          stop.disabled=true;
          try{await request("/api/manual-workflows/"+encodeURIComponent(w.id)+"/stop",{method:"POST"});await openGuided(w.id);}
          catch(e){notification(e.message,true);stop.disabled=false;}
        });root.appendChild(stop);
      }
      if(w.state==="stopping")root.appendChild(node("p","warning","Stop requested. Waiting for current safe tool boundary; no further stages or retries."));
      const optimizationVisible=w.pipeline_id && !["queued","scanning","patch_queued","patch_running","publishing","stopped","stopping"].includes(w.state);
      if(optimizationVisible&&(w.execution_mode==="auto_optimize"||w.optimization_active))optimizationPanel(root,w);
      if (w.pipeline_id && ["awaiting_approval","awaiting_publication","completed","completed_without_publish","published","patch_failed","publication_blocked"].includes(w.state)) {
        const planBox = node("div", "panel");
        const stage = ["awaiting_publication","completed_without_publish","published","publication_blocked"].includes(w.state) ? "residual" : "original";
        const planButton = node("button", "outline", "Review remediation plan");
        planButton.type = "button";
        const planResult = node("div");
        planButton.addEventListener("click", async () => {
          planButton.disabled = true;
          clear(planResult);
          try {
            const plan = await request("/api/remediation/" + encodeURIComponent(w.pipeline_id) + "/plan?stage=" + stage + "&limit=25");
            if (plan.status !== "planned") {
              planResult.appendChild(node("p", "info-note", "Verified evidence is not available for this stage."));
              return;
            }
            showMetrics(planResult, [["Package groups", plan.package_group_count], ["Findings (all severities)", plan.finding_count]]);
            const strategies = Object.entries(plan.strategy_summary).map(([name, counts]) => ({name: name.replaceAll("_"," "), ...counts}));
            detailsTable(planResult, [["Suggested strategy","name"],["Package groups","package_groups"],["Findings","findings"]], strategies);
            planResult.appendChild(node("p", "info-note", "Planning only; reported fixes are not verified package availability. Experimental paths do not execute."));
            const actions = plan.actions.map(x => ({package:x.package, severity:x.highest_severity, count:x.finding_count,
                strategy:x.preferred_strategy.replaceAll("_"," ")}));
            detailsTable(planResult, [["Priority package","package"],["Severity","severity"],["Findings","count"],["Suggested strategy","strategy"]], actions);
            if (plan.next_offset != null) planResult.appendChild(node("p","info-note","Showing the first 25 package groups. Full paginated plan is available through the API/MCP."));
          } catch (error) { planResult.appendChild(node("p","warning",error.message)); }
          finally { planButton.disabled = false; }
        });
        planBox.appendChild(planButton); planBox.appendChild(planResult);
        if(["admin","operator"].includes(state.user?.role)) {
          const advice=node("button","outline","Ask local AI for strategy suggestions");
          advice.type="button";
          const output=node("div");
          advice.addEventListener("click",async()=>{
            if(!window.confirm("Send minimized package names, CVE IDs and versions to the configured local Ollama model? No commands or approval will be executed."))return;
            advice.disabled=true;output.textContent="Waiting for local model…";
            try{
              const result=await request("/api/remediation/"+encodeURIComponent(w.pipeline_id)+"/ai-advice",
                {method:"POST",body:JSON.stringify({stage,offset:0,limit:25,consent:true})});
              clear(output);
              output.appendChild(node("p","info-note","Validated advice only · "+result.model+" · reviewed "+result.reviewed_action_count+" package groups."));
              detailsTable(output,[["Package","package"],["Strategy","strategy"],["Reason","reason_code"]],result.selections);
              if(result.next_offset!=null)output.appendChild(node("p","hint","First batch only; remaining groups can be reviewed via the paginated API."));
            }catch(e){output.textContent=e.message;}finally{advice.disabled=false;}
          });
          planBox.appendChild(advice);planBox.appendChild(output);
        }
        root.appendChild(planBox);
      }
      if (!w.unattended && w.state === "awaiting_approval" && !w.optimization_active &&
          ["admin", "operator"].includes(state.user?.role)) {
        const controls = section(root, "Your decision is required");
        controls.appendChild(node("p", "info-note", "Scan complete. Review the findings below, then choose how to finish this workflow."));
        const actionRow = node("div", "approval-actions");
        const finish = node("button", "outline", "✓ Finish without patching");
        finish.type = "button"; finish.addEventListener("click", () => decideGuided(w.id, "finish"));
        actionRow.appendChild(finish);
        const eligibility = data.patch_eligibility;
        if (eligibility && eligibility.os_fixable != null) {
          showMetrics(controls, [["OS with known fix", eligibility.os_fixable],
            ["OS without known fix", eligibility.os_no_known_fix],
            ["Application with known fix", eligibility.application_fixable],
            ["Application without known fix", eligibility.application_no_known_fix]]);
          controls.appendChild(node("p", "info-note", "Eligibility uses all severities, including LOW retained in raw evidence. Application fixes require dependency updates/rebuilds."));
        }
        if (data.patch_enabled && eligibility?.eligible) {
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
          controls.appendChild(node("p", "info-note", !data.patch_enabled ?
            "Patching is disabled in this deployment. You can finish without patching." :
            (eligibility?.message || "Verified original scan required before patching.")));
        }
        controls.appendChild(actionRow);
      }
      const scans = pipeline?.scans || [], artifacts = pipeline?.artifacts || [], patches = pipeline?.patches || [], diffs = pipeline?.diffs || [];
      const orig = scans.find(s => s.phase === "original"), patched = scans.find(s => s.phase === "patched");
      const intel=orig?.evidence?.fix_discovery, fleet=orig?.evidence?.fleet_plan;
      if(intel||fleet){
        const box=section(root,"V4 Fix Discovery & signed binary plan");
        if(intel){
          box.appendChild(node("p","info-note","Vendor evidence: "+intel.status+(intel.message?" — "+intel.message:"")));
          const summary=intel.summary?.trivy;
          if(summary)showMetrics(box,[["OS findings",summary.os_finding_occurrences],["Scanner FixedVersion missing",summary.blank_fixed_version]]);
          if(summary?.all_categories)detailsTable(box,[["Vendor evidence","category"],["Findings","count"]],Object.entries(summary.all_categories).map(([category,count])=>({category,count})));
        }
        if(fleet){
          box.appendChild(node("p","info-note","Repository plan: "+fleet.status+(fleet.message?" — "+fleet.message:"")+(fleet.mirror?" · "+fleet.mirror:"")));
          detailsTable(box,[["Package","package"],["Before","before"],["Candidate","after"]],Object.entries(fleet.updates||{}).map(([packageName,values])=>({package:packageName,...values})));
        }
        box.appendChild(node("p","info-note","Local test only. Source fixes are not installable binary fixes. No package removal or custom build."));
      }
      const sbomReady = artifacts.some(a => a.kind === "sbom" && (!orig || a.scan_id === orig.id));
      const sec = section(root, "Step-by-step progress");
      const ol = node("ol", "manual-timeline");
      const scanFailed = w.scan_job_status === "failed";
      stepItem(ol, "1. Queue and scan image", "Trivy inspects the actual image and saves vulnerability findings.", scanFailed ? "failed" : w.scan_job_status === "success" ? "done" : w.scan_job_status === "running" ? "running" : "waiting");
      stepItem(ol, "2. Generate SBOM", "Generate a CycloneDX inventory of the original image's packages and dependencies.", sbomReady ? "done" : scanFailed ? "failed" : w.scan_job_status === "running" ? "running" : "waiting");
      stepItem(ol, "3. Review original findings", w.unattended?"Local actions authorized before Start.":"Human approval is needed before local patching.", w.decision || (w.unattended&&w.optimization_active) ? "done" : w.state === "awaiting_approval" ? "running" : "waiting");
      const terminal=["published","completed","completed_without_publish","failed","patch_failed","publish_failed","stopped","canceled"].includes(w.state);
      const noCopa=!w.patch_job_id&&(terminal||w.optimization_active);
      const reason=w.execution_mode==="scan_only"?"Scan-only route selected.":data.patch_eligibility?.code==="NO_FIXABLE_OS"?"No OS findings have a reported FixedVersion; targeted Copa was skipped.":"No separate Copa job was executed.";
      const patchStrategy=pipeline?.patches?.[0]?.strategy;
      stepItem(ol,(intel||fleet)?"4. V4 signed package remediation":"4. Copa "+(patchStrategy?patchStrategy+" ":"")+"patch",fleet?.status==="no_updates"?"No eligible binary updates in approved repositories.":noCopa?reason:(intel||fleet)?"Check all installed packages; retain local candidate only.":patchStrategy==="comprehensive"?"Comprehensive OS updates; no FixedVersion requirement.":"Build a local OS patch using Copa / BuildKit.",noCopa?"skipped":w.patch_job_status==="success"?"done":w.patch_job_status==="failed"?"failed":w.decision==="approve_patch"?"running":"waiting");
      stepItem(ol,"5. Patched image rescan",noCopa?"No patched image to rescan.": "Trivy scans the actual local patch output.",noCopa?"skipped":patched?.status==="success"&&diffs.length?"done":w.patch_job_status==="failed"?"failed":w.decision==="approve_patch"?"running":"waiting");
      if(w.execution_mode==="auto_optimize")stepItem(ol,"6. Optimize and rescan candidate","Compare the original and final candidate with the same frozen vulnerability DB.",pipeline?.optimization?.state==="completed"?"done":w.optimization_active?"running":pipeline?.optimization?.state==="failed"?"failed":terminal?"skipped":"waiting");
      stepItem(ol,w.execution_mode==="auto_optimize"?"7. Registry publication":"6. Registry publication",w.unattended&&!w.auto_destination?"Local output selected before Start; registry push not requested.":"Publish only with applicable authorization and verified evidence.",w.state==="published"?"done":w.state==="publishing"?"running":w.unattended&&!w.auto_destination||noCopa?"skipped":w.state==="publish_failed"?"failed":w.publish_decision==="skip_publish"?"skipped":"waiting");
      stepItem(ol,w.execution_mode==="auto_optimize"?"8. Final report":"7. Final report","Display original and actual final candidate findings; no invented patch result.",["published","completed","completed_without_publish"].includes(w.state)?"done":terminal?"failed":"waiting");
      sec.appendChild(ol);
      if (pipeline?.pipeline) {
        renderUnifiedSummary(root, pipeline);
        root.appendChild(button("Open detailed findings →", () => openPipeline(w.pipeline_id)));
      }
      if (!w.unattended && ["awaiting_publication", "publication_blocked"].includes(w.state) && !w.optimization_active &&
          ["admin", "operator"].includes(state.user?.role)) {
        const controls = section(root, "Final review: publish or stop");
        const lastPatch = patches[0];
        controls.appendChild(node("p", "info-note",
          "Prepared image: " + (lastPatch?.patched_image_ref || "Unavailable") +
          ". The patched version was scanned locally. No registry push has happened."));
        const actions = node("div", "approval-actions");
        const local = patches[0]?.local_image_ref;
        controls.appendChild(node("p","info-note","Local Docker tag: "+(local||"Not recorded")+
          ". Keep the image on this WSL Docker host without a registry Push."));
        const stop = node("button", "outline", "Keep patched image locally");
        stop.type = "button";
        stop.addEventListener("click", () => decideGuided(w.id, "skip_publish"));
        actions.appendChild(stop);
        if (w.state === "awaiting_publication" && data.patch_enabled &&
            ["admin", "operator"].includes(state.user?.role)) {
          const warn = node("p", "warning",
            "This is a separate registry write. The post-fix recommendation is advisory, not a gate. Always review CVEs and validate the exact destination before approving.");
          controls.appendChild(warn);
          const destLabel=node("label","", "Destination image (registry.example.org/team/image:tag)");
          destLabel.htmlFor="publish-destination";
          const destInput=document.createElement("input");destInput.id="publish-destination";
          destInput.value=lastPatch?.patched_image_ref||data.registry_destination||"";
          destInput.placeholder="registry.example.org/team/patched:1";
          destInput.style.width="100%";destInput.style.padding="11px";
          controls.appendChild(destLabel);controls.appendChild(destInput);
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
            "Post-fix rescan or recommendation is not yet complete. You can keep the local image, but cannot approve a registry push yet."));
        }
        if (data.requires_second_approver) {
          controls.appendChild(node("p", "info-note",
            "Two-person approval is required: the operator approving publication must differ from the patch reviewer."));
        }
        controls.appendChild(actions);
      }

      if (["failed", "patch_failed", "publish_failed"].includes(w.state)) {
        const failure = w.publish_error || w.patch_error || w.scan_error;
        root.appendChild(node("p", "warning", "Operation failed: " +
          (failure || "See job diagnostics and ask an administrator for the correlation ID.")));
        if (((w.state === "failed" && w.scan_job_status === "failed") ||
             (w.state === "patch_failed" && data.patch_eligibility?.code === "NO_FIXABLE_OS" &&
              data.diagnostics?.some(x => x.code === "NO_FIXABLE_OS"))) &&
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
          item.appendChild(node("strong", "", "["+info.stage+"] "+info.code + " — " + info.title));
          if(info.detail)item.appendChild(node("pre","diagnostic-detail",info.detail));
          item.appendChild(node("p", "muted", "How to fix: "+info.hint));
          diagnostics.appendChild(item);
        });
      }
      if (pipeline?.artifacts?.length) {
        const details=node("details","advanced-evidence");
        details.appendChild(node("summary","","Raw JSON and SBOM (advanced)"));
        const links=node("div","results-list");
        pipeline.artifacts.forEach(a=>{
          const link=node("a","mini-link",a.kind+" · "+a.format+" ↗");
          link.href=prefix+"/api/artifacts/"+encodeURIComponent(a.id)+"/download";
          link.rel="noopener";link.target="_blank";links.appendChild(link);
        });
        details.appendChild(links);root.appendChild(details);
      }
      if(optimizationVisible&&!w.unattended&&w.execution_mode!=="auto_optimize"&&!w.optimization_active)optimizationPanel(root,w);
      if(state.user?.role==="admin"&&w.pipeline_id) {
        const danger=node("div","history-danger");
        danger.appendChild(button("Delete this workflow & history",()=>deletePipelineHistory(w.pipeline_id)));
        root.appendChild(danger);
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

  async function loadToolUpdates() {
    if (state.user?.role !== "admin") return;
    const items = await request("/api/tool-updates");
    const badge = $("tool-update-count"), count = items.filter(x => x.update_available).length;
    badge.hidden = !count; badge.textContent = count ? "(" + count + " updates)" : "";
    const holder = $("tool-updates-body"); clear(holder);
    for (const item of items) {
      const row = node("tr");
      cell(row, item.tool); cell(row, item.current_version || "Not detected"); cell(row, item.latest_version || "Not checked");
      const names = {current:"Current",available:"Update available",failed:"Update failed",check_failed:"Release check failed",queued:"Queued",applying:"Applying",unchecked:"Not checked"};
      const status = cell(row, ""); status.appendChild(node("span", "pill " + (item.status === "current" ? "success" : item.status.includes("failed") ? "failed" : item.status === "available" ? "patch" : item.status === "applying" ? "running" : item.status), names[item.status] || item.status));
      if(item.last_error) status.appendChild(node("p","small-text",item.last_error));
      if(item.status === "check_failed" && item.latest_version) status.appendChild(node("p","info-note","Latest stable is the last known release, not a fresh check."));
      cell(row, date(item.checked_at));
      const action=cell(row,"");
      if(item.update_available && !["queued","applying"].includes(item.status)) {
        action.appendChild(button(item.status === "failed" ? "Retry update" : "Apply update", async () => {
          if(!window.confirm("Apply "+item.tool+" "+item.latest_version+" to future jobs?"))return;
          try { await request("/api/tool-updates/"+encodeURIComponent(item.tool)+"/apply",{method:"POST"});
            await loadToolUpdates();notification("Update queued; watch the state here.");
          } catch(error){notification(error.message,true);}
        }));
      } else { action.textContent = "—"; }
      holder.appendChild(row);
    }
  }
  $("tool-check").addEventListener("click", async () => {
    try { await request("/api/tool-updates/check",{method:"POST"});notification("Release check queued.");await loadToolUpdates(); }
    catch(error){notification(error.message,true);}
  });
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
    await loadToolUpdates();
  }

  async function loadPolicyRules() {
    const project = $("policy-project").value;
    const query = project ? "?project_id=" + encodeURIComponent(project) : "";
    const rules = await request("/api/policies/effective" + query);
    if ($("policy-project").value !== project) return;
    // All policy decisions are now advisory after the second scan.
    for (const severity of ["critical", "high", "medium", "low", "unknown"]) {
      $("policy-" + severity).value = rules["max_" + severity] ?? (severity === "unknown" ? 0 : 999999);
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
      document.dispatchEvent(new CustomEvent("appsec:view", {detail:{view:"users"}}));
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
      enforce: false,
      max_critical: Number($("policy-critical").value),
      max_high: Number($("policy-high").value),
      max_medium: Number($("policy-medium").value),
      max_low: Number($("policy-low").value),
      max_unknown: Number($("policy-unknown").value)
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
  $("report-back").addEventListener("click", () => selectView(reportReturnView === "results" ? "overview" : reportReturnView));
  document.addEventListener("appsec:open-workflow", event => openGuided(event.detail.id));
  document.addEventListener("appsec:open-pipeline", event => openPipeline(event.detail.id));
  $("refresh-button").addEventListener("click", async () => { quiet(); try { await refreshOverview(); } catch (e) { notification(e.message, true); } });
  $("health-refresh-button").addEventListener("click", async () => { try { await refreshSystemHealth(); } catch (e) { notification(e.message, true); } });
  $("guided-refresh").addEventListener("click", async () => { try { await refreshGuided(); if (state.selectedWorkflow) await openGuided(state.selectedWorkflow); } catch (e) { notification(e.message, true); } });
  $("execution-mode").addEventListener("change",()=>{
    const mode=$("execution-mode").value;
    $("optimization-choices").hidden=mode!=="auto_optimize";
    $("patch-output-choices").hidden=mode!=="auto_patch";
    $("execution-help").textContent=({guided:"Review the initial scan and decide whether to patch.",scan_only:"Scan and SBOM only; no local patch.",auto_patch:"Automatically prepare a local package patch and rescan. In V4 fleet-test deployments, use signed Debian binary upgrades independent of FixedVersion; select local output only.",auto_optimize:"Automatically try Copa targeted or comprehensive updates, then simulate removal of the selected unused modules and safe dependency closure, build and rescan locally, then finish. No registry push."})[mode];
  });
  $("auto-push").addEventListener("change",()=>{ $("auto-destination").disabled=!$("auto-push").checked; });
  async function loadPackageMirrors(){
    const data=await request("/api/optimization/mirrors");
    $("package-mirror-choice").value=data.selected.join(",");
    $("package-mirror-feedback").textContent=data.enabled?"Optimization enabled":"Optimization disabled on worker";
  }
  $("save-package-mirrors").addEventListener("click",async()=>{
    const value=$("package-mirror-choice").value;
    try{
      await request("/api/optimization/mirrors",{method:"PUT",body:JSON.stringify({mirrors:value?value.split(","):[]})});
      $("package-mirror-feedback").textContent="Saved. Applies to future APT jobs.";
    }catch(e){notification(e.message,true);}
  });
  $("image-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (!state.user || state.user.role === "viewer") return notification("Viewer cannot start scans.", true);
    const mode=$("execution-mode").value;
    const roots=mode==="auto_optimize"?Array.from($("optimization-choices").querySelectorAll("input:checked:not(#optimization-authorize)"),x=>x.value):[];
    if(mode==="auto_optimize"&&!roots.length)return notification("Select at least one unused optional module.",true);
    if(mode==="auto_optimize"&&!$("optimization-authorize").checked)return notification("Confirm local removal of selected modules and the validated dependency closure before starting.",true);
    const destination=mode==="auto_patch"&&$("auto-push").checked?$("auto-destination").value.trim():null;
    if(mode==="auto_patch"&&$("auto-push").checked&&!destination)return notification("Enter the approved destination before starting.",true);
    const payload = { image: $("image-reference").value.trim(), project_id: $("image-project").value || null,execution_mode:mode,optimization_roots:roots,unattended:true,auto_destination:destination };
    try {
      const result = await request("/api/manual-workflows", { method: "POST", body: JSON.stringify(payload) });
      guidedPage = 1; selectedPipelines.clear();
      await openGuided(result.id);
      notification("Workflow queued with all selected actions and output. No additional decisions are required.");
    } catch (error) { notification(error.message, true); }
  });
  $("repo-form").addEventListener("submit", async event => {
    event.preventDefault();
    const payload = { kind: "secrets", target: $("repository-url").value.trim(), profile: $("repo-profile").value, project_id: $("repo-project").value || null, repo_username: $("repo-user").value || null, repo_password: $("repo-password").value || null };
    try {
      const result = await request("/api/security-jobs", { method: "POST", body: JSON.stringify(payload) });
      $("repo-password").value = ""; $("repo-user").value = "";
      selectView("overview"); await refreshOverview(); notification("Repository scan queued. Job ID: " + result.job_id);
    } catch (error) { notification(error.message, true); }
    finally { $("repo-password").value = ""; }
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
    if (state.user.role === "admin") loadToolUpdates().catch(() => {});
    if (state.view === "overview") {
      refreshOverview().catch(() => {});
      refreshHealth();
    }
    // Workflow details refresh on state transition in Live Watch; no repeated full report fetch.
    if (state.view === "guided" && !bulkBusy) refreshGuided().catch(() => {});
  }, 20000);
})();

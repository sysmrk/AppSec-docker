/* AppSec workspace: inventory, approvals, registry, users and profile.
   Pure browser UI; API authz and validation remain server-side. */
(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const dt = x => x ? new Date(x).toLocaleString() : "—";
  const element = (tag, value, className = "") => {
    const n = document.createElement(tag);
    n.textContent = value == null ? "—" : String(value);
    if (className) n.className = className;
    return n;
  };
  const button = (label, action, cls = "text-button") => {
    const b = element("button", label, cls);
    b.type = "button";
    b.addEventListener("click", action);
    return b;
  };
  const cell = (tr, value) => { const c = element("td", value); tr.appendChild(c); return c; };
  const clear = n => n.replaceChildren();
  const prefix = location.pathname.startsWith("/appsec-api/") ? "/appsec-api" : "";
  const state = { imageOffset: 0, imageQuery: "", selectedUser: null, selectedImage: null };
  const notice = (message, isError = false) => {
    const n = $("global-notice");
    n.textContent = message;
    n.className = "notice" + (isError ? " error" : "");
    n.hidden = false;
  };
  async function api(path, options = {}) {
    const r = await fetch(prefix + path, {
      credentials: "same-origin", cache: "no-store",
      headers: {"Accept": "application/json", "X-Requested-With": "AppSec-Control-Center",
        ...(options.body ? {"Content-Type": "application/json"} : {})},
      ...options
    });
    let data = null;
    try { data = await r.json(); } catch (_) { /* no body */ }
    if (!r.ok) {
      const info = data?.error;
      throw new Error((data?.detail || "Request failed: " + r.status) +
        (info?.hint ? ". " + info.hint : "") +
        (info?.request_id ? " [Request: " + info.request_id + "]" : ""));
    }
    return data;
  }
  async function send(path, body, method = "POST") {
    return api(path, {method, body: JSON.stringify(body)});
  }
  const empty = (body, count, title) => {
    const row = element("tr", "");
    const col = cell(row, title);
    col.colSpan = count;
    col.className = "empty-state";
    body.appendChild(row);
  };
  const field = (root, title, value) => {
    const row = element("div", "", "user-field");
    row.appendChild(element("strong", title));
    row.appendChild(element("span", value));
    root.appendChild(row);
  };
  const dateOr = d => d ? dt(d) : "Never";

  async function refreshInventory() {
    const q = encodeURIComponent(state.imageQuery);
    const data = await api("/api/images?q=" + q + "&limit=30&offset=" + state.imageOffset);
    const body = $("inventory-body"); clear(body);
    for (const item of data.items) {
      const row = document.createElement("tr");
      cell(row, item.name).className = "wide-text";
      cell(row, item.run_count);
      cell(row, item.last_status);
      cell(row, item.critical_count);
      cell(row, item.high_count);
      cell(row, dt(item.last_scanned_at));
      cell(row, "").appendChild(button("History →", () => openImage(item)));
      body.appendChild(row);
    }
    if (!data.items.length) empty(body, 7, "No matching real scans. Run a scan to populate this inventory.");
    $("inventory-page").textContent = "Page " + (1 + Math.floor(state.imageOffset / 30));
    $("inventory-prev").disabled = state.imageOffset === 0;
    $("inventory-next").disabled = data.items.length < 30;
  }

  async function openImage(item) {
    state.selectedImage = item.id;
    const history = await api("/api/images/" + encodeURIComponent(item.id) + "/history?limit=100");
    const root = $("inventory-detail"); clear(root);
    root.appendChild(element("h2", item.name));
    root.appendChild(element("p", "Actual scan history, most recent first.", "info-note"));
    const wrap = element("div", "", "table-wrap");
    const table = document.createElement("table");
    const header = document.createElement("tr");
    ["Date", "Status", "Phase", "Critical", "High", "Policy run"].forEach(v => header.appendChild(element("th", v)));
    table.appendChild(header);
    history.forEach(run => {
      const row = document.createElement("tr");
      cell(row, dt(run.started_at)); cell(row, run.status); cell(row, run.phase || "—");
      cell(row, run.critical_count); cell(row, run.high_count);
      const actions = cell(row, "");
      actions.appendChild(button("Open →", () => {
        const event = new CustomEvent("appsec:open-pipeline", {detail: {id: run.id}});
        document.dispatchEvent(event);
      }));
      table.appendChild(row);
    });
    wrap.appendChild(table); root.appendChild(wrap);
    const scans = history.filter(h => h.scan_id);
    if (scans.length >= 2) {
      const section = element("div", "", "compare-panel");
      section.appendChild(element("h2", "Compare two real scans"));
      section.appendChild(element("p", "Pick two scan results; new and fixed CVEs are compared by ID, package and target.", "hint"));
      const first = document.createElement("select"), second = document.createElement("select");
      first.setAttribute("aria-label", "Older scan");
      second.setAttribute("aria-label", "Newer scan");
      for (const scan of scans) {
        for (const select of [first, second]) {
          const opt = document.createElement("option");
          opt.value = scan.scan_id;
          opt.textContent = dt(scan.started_at) + " · " + scan.phase;
          select.appendChild(opt);
        }
      }
      second.selectedIndex = 0; first.selectedIndex = 1;
      const results = element("div", "", "compare-results");
      section.appendChild(first); section.appendChild(second);
      section.appendChild(button("Compare CVEs", async () => {
        if (first.value === second.value) return notice("Choose two different scans.", true);
        try {
          const d = await api("/api/images/compare/scans?from_scan=" +
            encodeURIComponent(first.value) + "&to_scan=" + encodeURIComponent(second.value) + "&limit=100");
          clear(results);
          for (const [name, value] of [
            ["Fixed", d.fixed_count], ["Still present", d.remaining_count], ["Introduced", d.introduced_count]
          ]) field(results, name, value);
          for (const [label, values] of [["Fixed vulnerabilities", d.fixed], ["New vulnerabilities", d.introduced]]) {
            results.appendChild(element("h3", label));
            const list = document.createElement("ul");
            values.forEach(v => list.appendChild(element("li", v.vulnerability_id + " · " +
              v.severity + " · " + v.pkg_name + " · " + (v.fixed_version || "no fix known"))));
            if (!values.length) list.appendChild(element("li", "None"));
            results.appendChild(list);
          }
          results.appendChild(element("p", "Up to 100 items are displayed in each category. Counts include all matching database findings.", "hint"));
        } catch (error) { notice(error.message, true); }
      }, "primary"));
      section.appendChild(results); root.appendChild(section);
    }
  }

  async function refreshApprovals() {
    const rows = await api("/api/manual-workflows?limit=100");
    const pending = rows.filter(w => ["awaiting_approval", "awaiting_publication", "publication_blocked"].includes(w.state));
    const body = $("approvals-body"); clear(body);
    pending.forEach(w => {
      const row = document.createElement("tr");
      cell(row, w.requested_image).className = "wide-text";
      cell(row, w.state === "awaiting_approval" ? "Review original scan" :
        w.state === "awaiting_publication" ? "Review patched image / publish" : "Policy blocked publication");
      cell(row, w.pipeline_status || "—");
      cell(row, dt(w.created_at));
      cell(row, "").appendChild(button("Review →", () =>
        document.dispatchEvent(new CustomEvent("appsec:open-workflow", {detail: {id: w.id}}))));
      body.appendChild(row);
    });
    if (!pending.length) empty(body, 5, "No pending decisions for your authorized Projects.");
  }

  async function refreshUsers() {
    const users = await api("/api/users");
    const body = $("users-body"); clear(body);
    users.forEach(u => {
      const row = document.createElement("tr");
      cell(row, u.username + " · " + u.display_name);
      cell(row, u.role);
      cell(row, u.disabled ? "Disabled" : u.locked_until && new Date(u.locked_until) > new Date()
        ? "Temporarily locked" : u.must_change_password ? "Password change required" : "Active");
      cell(row, dateOr(u.last_seen_at));
      cell(row, "").appendChild(button("Manage →", () => openUser(u.id)));
      body.appendChild(row);
    });
    if (!users.length) empty(body, 5, "No users found.");
  }

  function userActionRow(root, title, action, caution = false) {
    const wrap = document.createElement("div");
    wrap.className = "user-action-row";
    wrap.appendChild(element("strong", title));
    wrap.appendChild(button("Run action", action, caution ? "danger-button" : "outline"));
    root.appendChild(wrap);
  }

  async function openUser(id) {
    state.selectedUser = id;
    const detail = await api("/api/users/" + encodeURIComponent(id));
    const u = detail.user, root = $("user-detail");
    clear(root);
    root.appendChild(element("h2", u.username + " — " + u.display_name));
    const summary = element("div", "", "user-summary");
    field(summary, "Role", u.role);
    field(summary, "Account", u.disabled ? "Disabled" : "Enabled");
    field(summary, "Requires password change", u.must_change_password ? "Yes" : "No");
    field(summary, "Failed login attempts", u.failed_login_count);
    field(summary, "Lockout ends", dateOr(u.locked_until));
    field(summary, "Last used", dateOr(u.last_seen_at));
    field(summary, "Last password update", dateOr(u.password_changed_at));
    field(summary, "Last API key rotation", dateOr(u.api_key_rotated_at));
    field(summary, "Authenticator MFA", u.mfa_enabled ? "Enabled" : "Disabled");
    root.appendChild(summary);

    const form = element("form", "", "user-edit");
    const displayLabel = element("label", "Display name");
    const display = document.createElement("input"); display.value = u.display_name;
    const roleLabel = element("label", "Global role");
    const role = document.createElement("select");
    for (const value of ["admin", "operator", "viewer"]) {
      const opt = element("option", value); opt.value = value; role.appendChild(opt);
    }
    role.value = u.role;
    const disabledLabel = element("label", "", "approval-checkbox");
    const disabled = document.createElement("input"); disabled.type = "checkbox"; disabled.checked = u.disabled;
    disabledLabel.appendChild(disabled); disabledLabel.appendChild(element("span", "Disable this account"));
    form.appendChild(displayLabel); form.appendChild(display);
    form.appendChild(roleLabel); form.appendChild(role);
    form.appendChild(disabledLabel);
    const save = element("button", "Save user changes", "primary"); save.type = "submit";
    form.appendChild(save);
    form.addEventListener("submit", async event => {
      event.preventDefault();
      if (disabled.checked && !u.disabled && !confirm("Disable this account and revoke all sessions?")) return;
      try {
        await send("/api/users/" + encodeURIComponent(id),
          {display_name: display.value.trim(), role: role.value, disabled: disabled.checked}, "PATCH");
        notice("User updated. Privilege changes revoke all active sessions.");
        await refreshUsers(); await openUser(id);
      } catch (error) { notice(error.message, true); }
    });
    root.appendChild(form);

    const actions = element("div", "", "user-security-actions");
    userActionRow(actions, "Reset password (require change on next login)", async () => {
      const password = prompt("Temporary password (12+ characters). Share securely with the user:");
      if (password === null) return;
      if (password.length < 12) return notice("Password must be at least 12 characters.", true);
      try {
        await send("/api/users/" + encodeURIComponent(id) + "/reset-password", {password});
        notice("Password reset; sessions revoked. Share new credentials securely.");
        await openUser(id);
      } catch (error) { notice(error.message, true); }
    }, true);
    userActionRow(actions, "Rotate API key (one-time reveal)", async () => {
      if (!confirm("Rotate API key? Existing automation using the old key will stop immediately.")) return;
      try {
        const r = await send("/api/users/" + encodeURIComponent(id) + "/rotate-api-key", {});
        const secret = element("pre", r.api_key, "one-time-secret");
        root.appendChild(element("p", "New API key — copy it securely now; it will not be shown again.", "warning"));
        root.appendChild(secret);
        notice("API key rotated. The old key has been invalidated.");
        await refreshUsers();
      } catch (error) { notice(error.message, true); }
    }, true);
    userActionRow(actions, "Revoke all web sessions", async () => {
      if (!confirm("Log this user out of every active web session?")) return;
      try {
        const result = await send("/api/users/" + encodeURIComponent(id) + "/revoke-sessions", {});
        notice(result.revoked + " sessions revoked."); await openUser(id);
      } catch (error) { notice(error.message, true); }
    }, true);
    root.appendChild(actions);

    const teams = element("div", "", "user-teams");
    teams.appendChild(element("h3", "Team membership"));
    for (const m of detail.teams) {
      const line = element("div", "", "user-action-row");
      line.appendChild(element("span", m.team_name + " · " + m.role));
      line.appendChild(button("Remove membership", async () => {
        if (!confirm("Remove this user from " + m.team_name + "? Project access may be revoked.")) return;
        try {
          await api("/api/teams/" + encodeURIComponent(m.team_id) + "/members/" +
            encodeURIComponent(id), {method: "DELETE"});
          notice("Membership removed."); await openUser(id);
        } catch (error) { notice(error.message, true); }
      }, "outline small"));
      teams.appendChild(line);
    }
    if (!detail.teams.length) teams.appendChild(element("p", "Not in any team.", "info-note"));
    root.appendChild(teams);
    const sessions = element("div", "", "user-teams");
    sessions.appendChild(element("h3", "Recent sessions"));
    for (const token of detail.sessions.slice(0,10)) {
      sessions.appendChild(element("p",
        dt(token.created_at) + " · " + (token.revoked_at ? "Revoked" :
          new Date(token.expires_at) <= new Date() ? "Expired" : "Active"), "info-note"));
    }
    root.appendChild(sessions);
  }

  async function refreshPullSources() {
    const rows=await api("/api/image-pull-sources");
    const body=$("pull-sources-body");clear(body);
    for(const source of rows){
      const tr=document.createElement("tr");
      cell(tr,source.name);cell(tr,source.host);
      const priority=element("input","");priority.type="number";priority.min="1";priority.max="10000";
      priority.value=String(source.priority);priority.className="priority-input";
      cell(tr,"").appendChild(priority);
      const enabled=element("input","");enabled.type="checkbox";enabled.checked=source.enabled;
      cell(tr,"").appendChild(enabled);
      const actions=cell(tr,"");
      actions.appendChild(button("Save",async()=>{
        try{
          await send("/api/image-pull-sources/"+encodeURIComponent(source.id),
            {priority:Number(priority.value),enabled:enabled.checked},"PUT");
          notice("Source priority saved. Lower numbers are pulled first.");await refreshPullSources();
        }catch(e){notice(e.message,true);}
      },"outline small"));
      actions.appendChild(button("Remove",async()=>{
        if(!confirm("Remove this image pull source? Future scans will stop using it."))return;
        try{await api("/api/image-pull-sources/"+encodeURIComponent(source.id),{method:"DELETE"});
          await refreshPullSources();notice("Source removed.");}catch(e){notice(e.message,true);}
      },"outline small"));
      body.appendChild(tr);
    }
    if(!rows.length)empty(body,5,"No source policy configured. Direct image pulls remain enabled until you add your first source.");
  }

  async function refreshRegistries() {
    const rows = await api("/api/registries");
    const body = $("registries-body"); clear(body);
    rows.forEach(reg => {
      const tr = document.createElement("tr");
      cell(tr, reg.name); cell(tr, reg.host); cell(tr, reg.project_id || "All");
      cell(tr, reg.allow_push ? "Configured (not credential-tested)" : "Scan-only");
      const action = cell(tr, "");
      action.appendChild(button("Remove", async () => {
        if (!confirm("Remove registry configuration " + reg.host + "? Existing scans stay intact.")) return;
        try {
          await api("/api/registries/" + encodeURIComponent(reg.id), {method: "DELETE"});
          notice("Registry removed."); await refreshRegistries();
        } catch (error) { notice(error.message, true); }
      }, "outline small"));
      body.appendChild(tr);
    });
    if (!rows.length) empty(body, 5, "No registries configured. Add one above; credentials remain on the worker.");
    await refreshPullSources();
    const projects = await api("/api/projects");
    const select = $("registry-project"); const old = select.value;
    while (select.options.length > 1) select.remove(1);
    projects.forEach(p => {
      const opt = element("option", p.name); opt.value = p.id; select.appendChild(opt);
    });
    if ([...select.options].some(o => o.value === old)) select.value = old;
  }

  $("inventory-refresh").addEventListener("click", () => refreshInventory().catch(e => notice(e.message, true)));
  $("inventory-prev").addEventListener("click", () => {
    state.imageOffset = Math.max(0, state.imageOffset - 30); refreshInventory().catch(e => notice(e.message, true));
  });
  $("inventory-next").addEventListener("click", () => {
    state.imageOffset += 30; refreshInventory().catch(e => notice(e.message, true));
  });
  $("inventory-search-form").addEventListener("submit", event => {
    event.preventDefault(); state.imageOffset = 0; state.imageQuery = $("inventory-search").value.trim();
    refreshInventory().catch(e => notice(e.message, true));
  });
  $("approvals-refresh").addEventListener("click", () => refreshApprovals().catch(e => notice(e.message, true)));
  $("users-refresh").addEventListener("click", () => refreshUsers().catch(e => notice(e.message, true)));
  $("pull-source-form").addEventListener("submit",async event=>{
    event.preventDefault();
    try{
      await send("/api/image-pull-sources",{
        name:$("pull-source-name").value.trim(),
        host:$("pull-source-host").value.trim(),
        priority:Number($("pull-source-priority").value),
        enabled:true
      });
      notice("Trusted source added. Future image pulls follow strictly sorted priorities; no Docker Hub fallback.");
      await refreshPullSources();
    }catch(error){notice(error.message,true);}
  });
  $("registry-form").addEventListener("submit", async event => {
    event.preventDefault();
    try {
      await send("/api/registries", {
        name: $("registry-name").value.trim(),
        host: $("registry-host").value.trim(),
        project_id: $("registry-project").value || null,
        allow_push: $("registry-allow-push").checked
      });
      notice("Registry metadata saved. Docker credentials and image pull remain unverified.");
      await refreshRegistries();
    } catch (error) { notice(error.message, true); }
  });
  $("scan-preflight").addEventListener("click", async () => {
    const image = $("image-reference").value.trim();
    if (!image) return notice("Enter a registry image reference first.", true);
    const root = $("scan-preflight-result");
    root.hidden = false; root.textContent = "Checking real configuration and Worker status…";
    try {
      const data = await api("/api/preflight/image?image=" + encodeURIComponent(image));
      clear(root);
      if(data.sources?.length){
        const order=element("div","Image source order: "+data.sources.map(s=>s.priority+". "+s.ref).join(" → "),"preflight-line");
        root.appendChild(order);
      }
      data.checks.forEach(c => {
        const line = element("div", "", "preflight-line " + c.status);
        line.appendChild(element("strong", c.name + ": " + c.status.toUpperCase()));
        line.appendChild(element("span", c.hint)); root.appendChild(line);
      });
    } catch (error) { root.textContent = error.message; notice(error.message, true); }
  });
  $("profile-password-form").addEventListener("submit", async event => {
    event.preventDefault();
    const value = $("profile-new-password").value;
    if (value !== $("profile-confirm-password").value) return notice("New passwords do not match.", true);
    try {
      await send("/api/profile/password", {
        current_password: $("profile-current-password").value, new_password: value
      });
      $("profile-current-password").value = "";
      $("profile-new-password").value = "";
      $("profile-confirm-password").value = "";
      $("profile-feedback").textContent = "Password updated and previous sessions revoked. Sign in again.";
      notice("Password changed. Please sign in again.");
      document.getElementById("logout-button").click();
    } catch (error) { notice(error.message, true); }
  });


  async function refreshProfileMFA() {
    const user = await api("/api/profile");
    $("profile-rotation-hint").hidden = !user.must_change_password;
    $("profile-mfa-status").textContent = user.mfa_enabled
      ? "Authenticator MFA is enabled. Each interactive login requires a fresh 6-digit code or one unused recovery code."
      : "Authenticator MFA is not enabled. You can enroll using your current password and an authenticator app.";
    $("mfa-enroll-form").hidden = Boolean(user.mfa_enabled || user.must_change_password);
    $("mfa-disable-form").hidden = !user.mfa_enabled;
  }
  $("mfa-enroll-form").addEventListener("submit", async event => {
    event.preventDefault();
    try {
      const answer = await send("/api/profile/mfa/enroll", {
        current_password: $("mfa-enroll-password").value
      });
      $("mfa-enroll-password").value = "";
      $("mfa-secret-value").textContent = answer.secret;
      $("mfa-setup-result").hidden = false;
      notice("MFA setup started. Confirm a code from the new authenticator entry within 10 minutes.");
    } catch (error) { notice(error.message, true); }
  });
  $("mfa-secret-copy").addEventListener("click", async () => {
    const secret = $("mfa-secret-value").textContent;
    try {
      await navigator.clipboard.writeText(secret);
      notice("Authenticator secret copied. Do not paste it into untrusted applications.");
    } catch (_) {
      notice("Copy permission unavailable. Select the secret manually.", true);
    }
  });
  $("mfa-confirm-form").addEventListener("submit", async event => {
    event.preventDefault();
    try {
      const result = await send("/api/profile/mfa/confirm", {code: $("mfa-confirm-code").value.trim()});
      $("mfa-confirm-code").value = "";
      $("mfa-secret-value").textContent = "";
      $("mfa-setup-result").hidden = true;
      $("mfa-enroll-form").hidden = true;
      $("mfa-recovery-values").textContent = result.recovery_codes.join("\n");
      $("mfa-recovery-result").hidden = false;
      notice("MFA enabled and all web sessions revoked. Save the recovery codes before continuing.");
    } catch (error) { notice(error.message, true); }
  });
  $("mfa-recovery-confirm").addEventListener("click", () => {
    $("mfa-recovery-values").textContent = "";
    $("mfa-recovery-result").hidden = true;
    $("logout-button").click();
  });
  $("mfa-disable-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (!confirm("Disable MFA and revoke all web sessions for this account?")) return;
    try {
      await send("/api/profile/mfa/disable", {
        current_password: $("mfa-disable-password").value,
        code: $("mfa-disable-code").value.trim()
      });
      $("mfa-disable-password").value = "";
      $("mfa-disable-code").value = "";
      notice("MFA disabled. Sign in again.");
      $("logout-button").click();
    } catch (error) { notice(error.message, true); }
  });

  document.addEventListener("appsec:view", e => {
    const view = e.detail?.view;
    const runners = {
      inventory: refreshInventory, approvals: refreshApprovals,
      users: refreshUsers, registries: refreshRegistries,
      profile: refreshProfileMFA
    };
    if (runners[view]) runners[view]().catch(error => notice(error.message, true));
  });
})();

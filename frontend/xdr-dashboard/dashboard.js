const SOURCE_DEFS = [
  { key: "edr", name: "EDR", short: "ED", description: "Endpoint telemetry", className: "source-edr" },
  { key: "wazuh", name: "Wazuh", short: "WZ", description: "SIEM / host events", className: "source-wazuh" },
  { key: "suricata", name: "Suricata", short: "SU", description: "Network IDS alerts", className: "source-suricata" },
];
const SEVERITIES = [
  { name: "Critical", color: "#ff5268" },
  { name: "High", color: "#ff7985" },
  { name: "Medium", color: "#ffb85e" },
  { name: "Low", color: "#55d6a0" },
  { name: "Info", color: "#68b6e8" },
];
const AI_FEATURE_LABELS = {
  process_count: "Số process được tạo",
  unique_process_images: "Số chương trình khác nhau",
  shell_process_count: "PowerShell / cmd",
  lolbin_process_count: "LOLBin (certutil, rundll32...)",
  suspicious_cmdline_count: "Command line đáng ngờ",
  max_cmdline_length: "Command line dài nhất",
  user_writable_exec_count: "Chạy từ Temp/AppData/Public",
  office_spawn_count: "Office sinh process con",
  network_connect_count: "Số kết nối mạng",
  unique_dst_ip: "Số IP đích khác nhau",
  unique_dst_port: "Số cổng đích khác nhau",
  external_connection_count: "Kết nối ra Internet",
  dns_query_count: "Số truy vấn DNS",
  unique_domains: "Số domain khác nhau",
  max_domain_entropy: "Entropy domain (DGA)",
  file_create_count: "Số file được tạo",
  executable_file_create_count: "File thực thi được tạo",
  registry_set_count: "Số lần ghi registry",
  persistence_registry_count: "Ghi Run key / Services",
  lsass_access_count: "Truy cập LSASS",
  auth_failure_count: "Đăng nhập thất bại",
};
const state = {
  events: [], alerts: [], hosts: [], incidents: [], aiStatus: null, aiWindows: [], loading: false,
};
let apiKey = "";
let authGeneration = 0;
let currentUser = null;
const byId = (id) => document.getElementById(id);
const numberFormat = new Intl.NumberFormat("vi-VN");

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function dateValue(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatDate(value) {
  const date = dateValue(value);
  return date ? new Intl.DateTimeFormat("vi-VN", { dateStyle: "short", timeStyle: "medium" }).format(date) : "Không rõ";
}

function normalizedSeverity(value) {
  const severity = String(value || "info").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(severity) ? severity : "info";
}

function sourceDefinition(value) {
  const source = String(value || "unknown").toLowerCase();
  return SOURCE_DEFS.find((item) => source === item.key || source.includes(item.key))
    || { key: "other", name: value || "Unknown", className: "" };
}

async function apiGet(path) {
  const response = await fetch(path, {
    headers: { Accept: "application/json", Authorization: `Bearer ${apiKey}` },
    cache: "no-store",
  });
  if (!response.ok) {
    const body = await response.text();
    const error = new Error(`${path} → HTTP ${response.status}${body ? `: ${body.slice(0, 180)}` : ""}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${apiKey}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
    cache: "no-store",
  });
  if (!response.ok) {
    const body = await response.text();
    const error = new Error(`${path} → HTTP ${response.status}${body ? `: ${body.slice(0, 180)}` : ""}`);
    error.status = response.status;
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

function showLogin(message = "") {
  byId("auth-error").textContent = message;
  byId("auth-error").hidden = !message;
  if (!byId("auth-dialog").open) byId("auth-dialog").showModal();
  byId("login-username").focus();
}

async function authenticateDashboard(event) {
  event.preventDefault();
  const username = byId("login-username").value.trim();
  const password = byId("login-password").value;
  const button = byId("auth-form").querySelector("button[type=submit]");
  button.disabled = true;
  byId("auth-error").hidden = true;
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ username, password }),
      cache: "no-store",
    });
    if (!response.ok) {
      const body = await response.json();
      throw new Error(body.detail || "Tên đăng nhập hoặc mật khẩu không đúng.");
    }
    const result = await response.json();
    apiKey = result.access_token;
    currentUser = result.user;
    authGeneration += 1;
    byId("login-password").value = "";
    byId("auth-dialog").close();
    byId("change-password-button").hidden = false;
    byId("logout-button").hidden = false;
    byId("user-management-button").hidden = currentUser.role !== "admin";
    byId("response-management-button").hidden = currentUser.role !== "admin";
    byId("ai-analyze-button").hidden = !["admin", "analyst"].includes(currentUser.role);
    byId("avatar").textContent = currentUser.username.slice(0, 2).toUpperCase();
    byId("avatar").title = `${currentUser.username} · ${currentUser.role}`;
    byId("api-state").textContent = `${currentUser.username} · ${currentUser.role}`;
    await refreshDashboard();
  } catch (error) {
    showLogin(error.message || "Không xác thực được với XDR API.");
  } finally {
    button.disabled = false;
  }
}

function logoutDashboard(message = "") {
  apiKey = "";
  currentUser = null;
  authGeneration += 1;
  state.events = [];
  state.alerts = [];
  state.hosts = [];
  state.incidents = [];
  state.aiStatus = null;
  state.aiWindows = [];
  render();
  byId("api-state").textContent = "Chưa đăng nhập";
  byId("last-updated").textContent = "Chưa đồng bộ";
  byId("change-password-button").hidden = true;
  byId("logout-button").hidden = true;
  byId("user-management-button").hidden = true;
  byId("response-management-button").hidden = true;
  byId("ai-analyze-button").hidden = true;
  byId("avatar").textContent = "XA";
  byId("avatar").title = "XDR analyst";
  if (byId("users-dialog").open) byId("users-dialog").close();
  if (byId("password-dialog").open) byId("password-dialog").close();
  showLogin(message);
}

async function logoutFromDashboard() {
  let message = "";
  try {
    if (apiKey) await apiRequest("/api/auth/logout", { method: "POST" });
  } catch (error) {
    message = `Đăng xuất phía máy chủ thất bại: ${error.message}`;
  } finally {
    logoutDashboard(message);
  }
}

function renderUsers(users) {
  const roleOptions = (selected) => ["admin", "analyst", "viewer"].map((role) =>
    `<option value="${role}" ${role === selected ? "selected" : ""}>${role}</option>`).join("");
  byId("users-body").innerHTML = users.map((user) => `
    <tr data-user-id="${escapeHtml(user.user_id)}">
      <td>${escapeHtml(user.username)}${user.user_id === currentUser.user_id ? " (bạn)" : ""}</td>
      <td><select data-user-role aria-label="Role của ${escapeHtml(user.username)}">${roleOptions(user.role)}</select></td>
      <td><label class="user-active"><input data-user-active type="checkbox" ${user.is_active ? "checked" : ""} ${user.user_id === currentUser.user_id ? "disabled" : ""}/> Hoạt động</label></td>
      <td><button class="text-button" data-user-save type="button">Lưu</button></td>
    </tr>`).join("");
  byId("users-body").querySelectorAll("[data-user-save]").forEach((button) => {
    button.addEventListener("click", async () => {
      const row = button.closest("[data-user-id]");
      const role = row.querySelector("[data-user-role]").value;
      const isActive = row.querySelector("[data-user-active]").checked;
      const isSelf = row.dataset.userId === currentUser.user_id;
      button.disabled = true;
      try {
        await apiRequest(`/api/users/${encodeURIComponent(row.dataset.userId)}`, {
          method: "PATCH",
          body: JSON.stringify({ role, is_active: isActive }),
        });
        if (isSelf && role !== "admin") {
          logoutDashboard();
          return;
        }
        byId("user-error").hidden = true;
        await loadUsers();
      } catch (error) {
        if (error.status === 401) {
          logoutDashboard("Phiên đăng nhập hết hạn hoặc tài khoản đã bị khóa. Đăng nhập lại.");
        } else {
          byId("user-error").textContent = error.message;
          byId("user-error").hidden = false;
        }
      } finally {
        button.disabled = false;
      }
    });
  });
}

async function loadUsers() {
  renderUsers(await apiGet("/api/users"));
}

async function createDashboardUser(event) {
  event.preventDefault();
  const form = byId("user-create-form");
  const data = new FormData(form);
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    await apiRequest("/api/users", {
      method: "POST",
      body: JSON.stringify({
        username: data.get("username"),
        password: data.get("password"),
        role: data.get("role"),
      }),
    });
    form.reset();
    byId("user-error").hidden = true;
    await loadUsers();
  } catch (error) {
    if (error.status === 401) {
      logoutDashboard("Phiên đăng nhập hết hạn hoặc tài khoản đã bị khóa. Đăng nhập lại.");
    } else {
      byId("user-error").textContent = error.message;
      byId("user-error").hidden = false;
    }
  } finally {
    button.disabled = false;
  }
}

async function openUserManagement() {
  try {
    await loadUsers();
    byId("user-error").hidden = true;
    byId("users-dialog").showModal();
  } catch (error) {
    if (error.status === 401) {
      logoutDashboard("Phiên đăng nhập hết hạn hoặc tài khoản đã bị khóa. Đăng nhập lại.");
    } else {
      byId("error-banner").textContent = `Không tải được tài khoản: ${error.message}`;
      byId("error-banner").hidden = false;
    }
  }
}

async function changeDashboardPassword(event) {
  event.preventDefault();
  const form = byId("password-form");
  const values = new FormData(form);
  const newPassword = values.get("new_password");
  if (newPassword !== values.get("confirm_password")) {
    byId("password-error").textContent = "Mật khẩu nhập lại không khớp.";
    byId("password-error").hidden = false;
    return;
  }
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    await apiRequest("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: values.get("current_password"),
        new_password: newPassword,
      }),
    });
    form.reset();
    byId("password-dialog").close();
    logoutDashboard("Mật khẩu đã được cập nhật. Đăng nhập lại bằng mật khẩu mới.");
  } catch (error) {
    if (error.status === 401) {
      logoutDashboard("Phiên đăng nhập hết hạn hoặc tài khoản đã bị khóa. Đăng nhập lại.");
    } else {
      byId("password-error").textContent = error.message;
      byId("password-error").hidden = false;
    }
  } finally {
    button.disabled = false;
  }
}

function updateResponseFields() {
  const action = byId("response-action").value;
  const hostField = byId("response-create-form").elements.host_id;
  const processField = byId("response-create-form").elements.process_id;
  const ipField = byId("response-create-form").elements.ip_address;
  byId("response-create-form").querySelector('[data-response-field="host_id"]').hidden = action === "block-ip";
  byId("response-create-form").querySelector('[data-response-field="process_id"]').hidden = action !== "kill-process";
  byId("response-create-form").querySelector('[data-response-field="ip_address"]').hidden = action !== "block-ip";
  hostField.required = action !== "block-ip";
  processField.required = action === "kill-process";
  ipField.required = action === "block-ip";
}

async function loadResponseRequests() {
  const requests = await apiGet("/api/response/requests");
  const actionNames = {
    kill_process: "Dừng process",
    block_ip: "Chặn IP",
    isolate_host: "Cô lập host",
  };
  byId("response-requests-body").innerHTML = requests.map((request) => {
    const target = Object.entries(request.target)
      .map(([key, value]) => `${key}: ${value}`)
      .join(", ");
    const status = request.status === "approved" ? "approved · chưa thực thi" : request.status;
    const canReview = request.status === "pending" && request.requested_by !== currentUser.user_id;
    return `<tr data-request-id="${escapeHtml(request.request_id)}" data-requester="${escapeHtml(request.requested_by)}">
      <td>${escapeHtml(actionNames[request.action] || request.action)}<small class="event-id">${escapeHtml(target)}</small></td>
      <td>${escapeHtml(request.reason)}<small class="event-id">Người tạo: ${escapeHtml(request.requested_by)}</small></td>
      <td>${escapeHtml(status)}</td>
      <td>${canReview ? '<button class="response-approve" data-review="approved" type="button">Duyệt</button><button class="response-reject" data-review="rejected" type="button">Từ chối</button>' : "—"}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="4" class="empty-row">Chưa có yêu cầu response.</td></tr>';
  byId("response-requests-body").querySelectorAll("[data-review]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await apiRequest(`/api/response/requests/${encodeURIComponent(button.closest("[data-request-id]").dataset.requestId)}`, {
          method: "PATCH",
          body: JSON.stringify({ status: button.dataset.review }),
        });
        byId("response-error").hidden = true;
        await loadResponseRequests();
      } catch (error) {
        if (error.status === 401) {
          logoutDashboard("Phiên đăng nhập hết hạn hoặc tài khoản đã bị khóa. Đăng nhập lại.");
        } else {
          byId("response-error").textContent = error.message;
          byId("response-error").hidden = false;
        }
      } finally {
        button.disabled = false;
      }
    });
  });
}

async function createResponseRequest(event) {
  event.preventDefault();
  const form = byId("response-create-form");
  const values = new FormData(form);
  const action = values.get("action");
  const payload = { reason: values.get("reason") };
  let endpoint = `/api/response/${action}`;
  if (action === "block-ip") {
    payload.ip_address = values.get("ip_address");
  } else {
    payload.host_id = values.get("host_id");
    if (action === "kill-process") payload.process_id = Number(values.get("process_id"));
  }
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    await apiRequest(endpoint, { method: "POST", body: JSON.stringify(payload) });
    form.reset();
    updateResponseFields();
    byId("response-error").hidden = true;
    await loadResponseRequests();
  } catch (error) {
    if (error.status === 401) {
      logoutDashboard("Phiên đăng nhập hết hạn hoặc tài khoản đã bị khóa. Đăng nhập lại.");
    } else {
      byId("response-error").textContent = error.message;
      byId("response-error").hidden = false;
    }
  } finally {
    button.disabled = false;
  }
}

async function openResponseManagement() {
  try {
    await loadResponseRequests();
    byId("response-error").hidden = true;
    byId("response-dialog").showModal();
  } catch (error) {
    if (error.status === 401) {
      logoutDashboard("Phiên đăng nhập hết hạn hoặc tài khoản đã bị khóa. Đăng nhập lại.");
    } else {
      byId("error-banner").textContent = `Không tải được yêu cầu response: ${error.message}`;
      byId("error-banner").hidden = false;
    }
  }
}

function renderSources() {
  const cards = SOURCE_DEFS.map((source) => {
    const count = state.events.filter((event) => sourceDefinition(event.source).key === source.key).length;
    const latest = state.events
      .filter((event) => sourceDefinition(event.source).key === source.key)
      .map((event) => dateValue(event.timestamp))
      .filter(Boolean)
      .sort((left, right) => right - left)[0];
    const status = count ? `Nhận event · mới nhất ${latest ? formatDate(latest) : "—"}` : "Chờ dữ liệu";
    return `<article class="source-card">
      <span class="source-logo ${source.className}">${source.short}</span>
      <span class="source-meta"><strong>${source.name}</strong><small>${status}</small></span>
      <span class="source-count">${numberFormat.format(count)}</span>
    </article>`;
  });
  byId("source-grid").innerHTML = cards.join("");
  byId("source-total").textContent = `${numberFormat.format(state.events.length)} event gần nhất`;
}

function renderSeverity() {
  const activeAlerts = state.alerts.filter((alert) => alert.status !== "resolved");
  byId("severity-total").textContent = numberFormat.format(activeAlerts.length);
  byId("metric-alerts").textContent = numberFormat.format(activeAlerts.length);
  const max = Math.max(1, ...SEVERITIES.map(({ name }) =>
    activeAlerts.filter((alert) => normalizedSeverity(alert.severity) === name.toLowerCase()).length));
  byId("severity-bars").innerHTML = SEVERITIES.map(({ name, color }) => {
    const count = activeAlerts.filter((alert) => normalizedSeverity(alert.severity) === name.toLowerCase()).length;
    return `<div class="severity-row"><span>${name}</span><span class="severity-track"><span class="severity-fill" style="display:block;width:${Math.round(count / max * 100)}%;background:${color}"></span></span><span class="severity-count">${count}</span></div>`;
  }).join("");
}

function renderActivity() {
  const now = Date.now();
  const start = now - 24 * 60 * 60 * 1000;
  const bins = Array(24).fill(0);
  for (const event of state.events) {
    const date = dateValue(event.timestamp);
    if (!date || date.getTime() < start || date.getTime() > now) continue;
    bins[Math.min(23, Math.floor((date.getTime() - start) / (60 * 60 * 1000)))] += 1;
  }
  const max = Math.max(1, ...bins);
  const middle = Math.ceil(max / 2);
  byId("chart-max").textContent = numberFormat.format(max);
  byId("chart-mid").textContent = numberFormat.format(middle);
  byId("activity-chart").innerHTML = bins.map((value, index) => {
    const height = Math.max(3, Math.round(value / max * 100));
    const hour = new Date(start + index * 60 * 60 * 1000).toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" });
    return `<span class="chart-bar" data-empty="${value === 0}" style="height:${height}%" title="${escapeHtml(hour)} · ${value} event"></span>`;
  }).join("");
}

function renderEvents() {
  const query = byId("event-search").value.trim().toLowerCase();
  const sourceFilter = byId("source-filter").value;
  const filtered = state.events.filter((event) => {
    const source = sourceDefinition(event.source).key;
    if (sourceFilter !== "all" && source !== sourceFilter) return false;
    const searchContent = [event.event_type, event.source, event.host_id, event.event_id, event.severity]
      .join(" ").toLowerCase();
    return !query || searchContent.includes(query);
  });
  byId("event-count-label").textContent = `${numberFormat.format(filtered.length)} event phù hợp`;
  if (!filtered.length) {
    const message = state.events.length ? "Không tìm thấy event phù hợp bộ lọc." : "XDR chưa lưu event nào.";
    byId("events-body").innerHTML = `<tr><td colspan="6" class="empty-row">${message}</td></tr>`;
    return;
  }
  byId("events-body").innerHTML = filtered.slice(0, 12).map((event, index) => {
    const source = sourceDefinition(event.source);
    const severity = normalizedSeverity(event.severity);
    return `<tr data-event-index="${index}" data-event-row>
      <td><span class="event-name">${escapeHtml(event.event_type)}</span><span class="event-id">${escapeHtml(event.event_id)}</span></td>
      <td><span class="source-pill ${source.className}">${escapeHtml(source.name)}</span></td>
      <td>${escapeHtml(event.host_id)}</td>
      <td><span class="severity-pill severity-${severity}">${escapeHtml(severity)}</span></td>
      <td class="time-cell">${escapeHtml(formatDate(event.timestamp))}</td>
      <td><button class="detail-button" type="button" aria-label="Xem chi tiết event">↗</button></td>
    </tr>`;
  }).join("");
  byId("events-body").querySelectorAll("[data-event-row]").forEach((row, index) => {
    row.addEventListener("click", () => showEventDetails(filtered[index]));
  });
}

function renderIncidents() {
  const active = state.incidents.filter((incident) => incident.status !== "resolved");
  byId("metric-incidents").textContent = numberFormat.format(active.length);
  if (!active.length) {
    byId("incidents-body").innerHTML = '<tr><td colspan="6" class="empty-row">Không có incident chưa resolved.</td></tr>';
    return;
  }
  byId("incidents-body").innerHTML = active.slice(0, 8).map((incident) => {
    const severity = normalizedSeverity(incident.severity);
    const status = String(incident.status || "open").toLowerCase();
    return `<tr>
      <td><span class="event-name">${escapeHtml(incident.title)}</span><span class="event-id">${escapeHtml(incident.incident_id)}</span></td>
      <td>${escapeHtml(incident.host_id)}</td>
      <td><span class="severity-pill severity-${severity}">${escapeHtml(severity)}</span></td>
      <td>${numberFormat.format((incident.alert_ids || []).length)}</td>
      <td class="time-cell">${escapeHtml(formatDate(incident.updated_at))}</td>
      <td><span class="status-pill status-${escapeHtml(status)}">${escapeHtml(status)}</span></td>
    </tr>`;
  }).join("");
}

function showToast(message) {
  const toast = byId("toast");
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("visible"), 4000);
}

function scoreText(value) {
  return Number(value || 0).toFixed(2);
}

function aiScoreCell(value) {
  const score = Math.max(0, Math.min(1, Number(value || 0)));
  const level = score >= 0.8 ? "high" : score >= 0.5 ? "mid" : "";
  return `<span class="ai-score"><span class="ai-score-track"><span class="ai-score-fill ${level}" style="width:${Math.round(score * 100)}%"></span></span><b>${scoreText(score)}</b></span>`;
}

function featureLabel(name) {
  return AI_FEATURE_LABELS[name] || name;
}

function featureChips(topFeatures) {
  if (!topFeatures || !topFeatures.length) return '<span class="ai-chip-none">Không feature nào vượt baseline</span>';
  return `<span class="ai-chips">${topFeatures.map((item) =>
    `<span class="ai-chip" title="${escapeHtml(item.feature)}: ${escapeHtml(item.value)} (baseline p99 ${escapeHtml(item.baseline_p99)})">${escapeHtml(featureLabel(item.feature))}: ${escapeHtml(item.value)}</span>`).join("")}</span>`;
}

function formatWindow(window) {
  const start = dateValue(window.window_start);
  const end = dateValue(window.window_end);
  if (!start) return "Không rõ";
  const time = (date) => date.toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" });
  return `${start.toLocaleDateString("vi-VN")} ${time(start)}–${end ? time(end) : ""}`;
}

function filteredAiWindows() {
  const host = byId("ai-host-filter").value;
  const anomaliesOnly = byId("ai-anomaly-filter").checked;
  return state.aiWindows.filter((window) =>
    (host === "all" || window.host_id === host) && (!anomaliesOnly || window.is_anomaly));
}

function renderAiStatus() {
  const status = state.aiStatus;
  const tag = byId("ai-state-tag");
  const enabled = Boolean(status && status.enabled);
  tag.className = `panel-tag ${enabled ? "ai-on" : "ai-off"}`;
  tag.innerHTML = `<span class="tiny-dot"></span> ${status ? (enabled ? "MODEL ĐANG HOẠT ĐỘNG" : "CHƯA CÓ MODEL") : "KHÔNG TẢI ĐƯỢC"}`;
  byId("ai-setup").hidden = !status || enabled;
  byId("ai-model-version").textContent = enabled ? status.version : "Chưa train";
  byId("ai-model-trained").textContent = enabled ? `Train lúc ${formatDate(status.trained_at)}` : "AI đang tắt";
  byId("ai-training-windows").textContent = enabled ? numberFormat.format(status.training_windows) : "—";
  byId("ai-training-caption").textContent = enabled
    ? `cửa sổ · FPR mục tiêu ${(status.target_fpr * 100).toFixed(1)}% · ${(status.hosts || []).length} host`
    : "cửa sổ dùng để train";
  const anomalies = state.aiWindows.filter((window) => window.is_anomaly).length;
  byId("ai-window-count").textContent = numberFormat.format(state.aiWindows.length);
  byId("ai-anomaly-count").textContent = numberFormat.format(anomalies);
  byId("ai-anomaly-caption").textContent = state.aiWindows.length
    ? `${((anomalies / state.aiWindows.length) * 100).toFixed(1)}% số cửa sổ đã chấm`
    : "cửa sổ vượt ngưỡng";
}

function renderAiTimeline() {
  const windows = state.aiWindows.slice(0, 72).reverse();
  if (!windows.length) {
    byId("ai-timeline").innerHTML = '<span class="empty-row">Chưa có cửa sổ nào được chấm.</span>';
    return;
  }
  byId("ai-timeline").innerHTML = windows.map((window, index) => {
    const height = Math.max(3, Math.round(Number(window.ai_score || 0) * 100));
    const title = `${window.host_id} · ${formatWindow(window)} · AI ${scoreText(window.ai_score)}`;
    return `<span class="ai-bar ${window.is_anomaly ? "anomaly" : ""}" data-ai-bar="${index}" style="height:${height}%" title="${escapeHtml(title)}"></span>`;
  }).join("");
  byId("ai-timeline").querySelectorAll("[data-ai-bar]").forEach((bar) => {
    bar.addEventListener("click", () => showAiWindow(windows[Number(bar.dataset.aiBar)]));
  });
}

function renderAiWindows() {
  const hostFilter = byId("ai-host-filter");
  const selected = hostFilter.value;
  const hosts = [...new Set(state.aiWindows.map((window) => window.host_id))].sort();
  hostFilter.innerHTML = '<option value="all">Tất cả host</option>' + hosts.map((host) =>
    `<option value="${escapeHtml(host)}">${escapeHtml(host)}</option>`).join("");
  hostFilter.value = hosts.includes(selected) ? selected : "all";

  const windows = filteredAiWindows();
  if (!windows.length) {
    const message = state.aiWindows.length ? "Không có cửa sổ phù hợp bộ lọc." : "Chưa có kết quả AI.";
    byId("ai-windows-body").innerHTML = `<tr><td colspan="6" class="empty-row">${message}</td></tr>`;
    return;
  }
  byId("ai-windows-body").innerHTML = windows.slice(0, 15).map((window, index) => `
    <tr data-event-row data-ai-window="${index}">
      <td><span class="event-name">${escapeHtml(window.host_id)}</span><span class="event-id">${escapeHtml(window.model_version)}</span></td>
      <td class="time-cell">${escapeHtml(formatWindow(window))}</td>
      <td>${numberFormat.format(window.event_count)}</td>
      <td>${aiScoreCell(window.ai_score)}</td>
      <td>${featureChips(window.top_features)}</td>
      <td><span class="status-pill ${window.is_anomaly ? "ai-verdict-anomaly" : "ai-verdict-normal"}">${window.is_anomaly ? "Bất thường" : "Bình thường"}</span></td>
    </tr>`).join("");
  byId("ai-windows-body").querySelectorAll("[data-ai-window]").forEach((row) => {
    row.addEventListener("click", () => showAiWindow(windows[Number(row.dataset.aiWindow)]));
  });
}

function renderAiAlerts() {
  const alerts = state.alerts
    .filter((alert) => alert.rule_id === "ai-anomaly" || Number(alert.ai_score) > 0)
    .sort((left, right) => Number(right.ai_score) - Number(left.ai_score));
  if (!alerts.length) {
    byId("ai-alerts-body").innerHTML = '<tr><td colspan="6" class="empty-row">Chưa có alert nào được AI chấm điểm.</td></tr>';
    return;
  }
  byId("ai-alerts-body").innerHTML = alerts.slice(0, 12).map((alert) => {
    const severity = normalizedSeverity(alert.severity);
    const status = String(alert.status || "open").toLowerCase();
    const source = alert.rule_id === "ai-anomaly" ? "AI" : `Rule · ${alert.rule_id}`;
    return `<tr>
      <td><span class="event-name">${escapeHtml(alert.title)}</span><span class="event-id">${escapeHtml(source)}</span></td>
      <td><span class="severity-pill severity-${severity}">${escapeHtml(severity)}</span></td>
      <td>${aiScoreCell(alert.ai_score)}</td>
      <td><strong>${numberFormat.format(alert.risk_score)}</strong>/100</td>
      <td class="ai-mitre">${escapeHtml((alert.mitre_attack || []).join(", ") || "—")}</td>
      <td><span class="status-pill status-${escapeHtml(status)}">${escapeHtml(status)}</span></td>
    </tr>`;
  }).join("");
}

function renderAi() {
  renderAiStatus();
  renderAiTimeline();
  renderAiWindows();
  renderAiAlerts();
}

function showAiWindow(window) {
  if (!window) return;
  const p99 = (state.aiStatus && state.aiStatus.feature_p99) || {};
  byId("ai-dialog-title").textContent = `${window.host_id} · ${window.is_anomaly ? "Bất thường" : "Bình thường"}`;
  byId("ai-dialog-meta").innerHTML = [
    `Cửa sổ: ${escapeHtml(formatWindow(window))}`,
    `AI score: ${escapeHtml(scoreText(window.ai_score))}`,
    `Event: ${escapeHtml(window.event_count)}`,
    `Model: ${escapeHtml(window.model_version)}`,
    window.alert_id ? `Alert: ${escapeHtml(window.alert_id)}` : "Không tạo alert",
  ].map((value) => `<span>${value}</span>`).join("");
  byId("ai-dialog-features").innerHTML = Object.entries(window.features || {}).map(([name, value]) => {
    const baseline = p99[name];
    const exceeded = baseline !== undefined && Number(value) > Number(baseline);
    return `<tr class="${exceeded ? "exceeded" : ""}">
      <td class="ai-mitre">${escapeHtml(name)}</td>
      <td>${escapeHtml(featureLabel(name))}</td>
      <td><strong>${escapeHtml(value)}</strong></td>
      <td>${baseline === undefined ? "—" : escapeHtml(Number(baseline).toFixed(2))}</td>
    </tr>`;
  }).join("");
  byId("ai-dialog").showModal();
}

async function loadAiData() {
  // AI endpoints are optional: a failure here must not break the rest of the dashboard.
  const [status, windows] = await Promise.all([
    apiGet("/api/ai/status").catch((error) => { if (error.status === 401) throw error; return null; }),
    apiGet("/api/ai/windows?limit=300").catch((error) => { if (error.status === 401) throw error; return []; }),
  ]);
  return { status, windows };
}

async function runAiAnalysis() {
  const button = byId("ai-analyze-button");
  button.disabled = true;
  try {
    const result = await apiRequest("/api/ai/analyze", { method: "POST" });
    if (result.status === "model_not_trained") {
      showToast("Chưa có model AI. Hãy train model trước (python -m ai.train).");
    } else {
      showToast(`AI đã chấm ${result.analyzed} cửa sổ mới, phát hiện ${result.anomalies} bất thường.`);
      await refreshDashboard();
    }
  } catch (error) {
    if (error.status === 401) {
      logoutDashboard("Phiên đăng nhập hết hạn hoặc tài khoản đã bị khóa. Đăng nhập lại.");
    } else {
      showToast(`Không chạy được AI: ${error.message}`);
    }
  } finally {
    button.disabled = false;
  }
}

function render() {
  byId("metric-events").textContent = numberFormat.format(state.events.length);
  byId("metric-event-caption").textContent = `Trong ${state.events.length >= 500 ? "500 event mới nhất" : "các event đã tải"}`;
  byId("metric-hosts").textContent = numberFormat.format(state.hosts.length);
  renderSeverity();
  renderActivity();
  renderSources();
  renderEvents();
  renderIncidents();
  renderAi();
}

function showEventDetails(event) {
  const dialog = byId("event-dialog");
  byId("dialog-title").textContent = event.event_type || "Event";
  byId("dialog-meta").innerHTML = [
    `Nguồn: ${escapeHtml(event.source)}`,
    `Host: ${escapeHtml(event.host_id)}`,
    `Severity: ${escapeHtml(event.severity)}`,
    `Thời gian: ${escapeHtml(formatDate(event.timestamp))}`,
    `ID: ${escapeHtml(event.event_id)}`,
  ].map((value) => `<span>${value}</span>`).join("");
  byId("dialog-raw").textContent = JSON.stringify(event.raw || {}, null, 2);
  dialog.showModal();
}

async function refreshDashboard() {
  if (state.loading || !apiKey) return;
  state.loading = true;
  const generation = authGeneration;
  const button = byId("refresh-button");
  button.disabled = true;
  byId("api-state").textContent = "Đang tải dữ liệu...";
  try {
    const [events, alerts, hosts, incidents, ai] = await Promise.all([
      apiGet("/api/events?limit=500"),
      apiGet("/api/alerts"),
      apiGet("/api/hosts"),
      apiGet("/api/incidents"),
      loadAiData(),
    ]);
    if (!apiKey || generation !== authGeneration) return;
    state.events = events;
    state.alerts = alerts;
    state.hosts = hosts;
    state.incidents = incidents;
    state.aiStatus = ai.status;
    state.aiWindows = ai.windows;
    byId("error-banner").hidden = true;
    byId("api-state").textContent = "Đang hoạt động";
    byId("last-updated").textContent = `Cập nhật ${new Date().toLocaleTimeString("vi-VN")}`;
    render();
  } catch (error) {
    if (!apiKey || generation !== authGeneration) return;
    if (error.status === 401) {
      logoutDashboard("Phiên đăng nhập hết hạn hoặc tài khoản đã bị khóa. Đăng nhập lại.");
    } else {
      byId("api-state").textContent = "Không kết nối API";
      byId("error-banner").textContent = `Không tải được dữ liệu từ XDR API: ${error.message}. Kiểm tra backend có đang chạy không rồi thử làm mới.`;
      byId("error-banner").hidden = false;
    }
  } finally {
    state.loading = false;
    button.disabled = false;
  }
}

byId("refresh-button").addEventListener("click", refreshDashboard);
byId("logout-button").addEventListener("click", logoutFromDashboard);
byId("change-password-button").addEventListener("click", () => {
  byId("password-error").hidden = true;
  byId("password-dialog").showModal();
});
byId("user-management-button").addEventListener("click", openUserManagement);
byId("response-management-button").addEventListener("click", openResponseManagement);
byId("view-all").addEventListener("click", refreshDashboard);
byId("auth-form").addEventListener("submit", authenticateDashboard);
byId("user-create-form").addEventListener("submit", createDashboardUser);
byId("password-form").addEventListener("submit", changeDashboardPassword);
byId("users-close").addEventListener("click", () => byId("users-dialog").close());
byId("response-close").addEventListener("click", () => byId("response-dialog").close());
byId("response-action").addEventListener("change", updateResponseFields);
byId("response-create-form").addEventListener("submit", createResponseRequest);
byId("event-search").addEventListener("input", renderEvents);
byId("source-filter").addEventListener("change", renderEvents);
byId("dialog-close").addEventListener("click", () => byId("event-dialog").close());
byId("ai-analyze-button").addEventListener("click", runAiAnalysis);
byId("ai-host-filter").addEventListener("change", renderAiWindows);
byId("ai-anomaly-filter").addEventListener("change", renderAiWindows);
byId("ai-dialog-close").addEventListener("click", () => byId("ai-dialog").close());
byId("ai-dialog").addEventListener("click", (event) => {
  if (event.target === byId("ai-dialog")) byId("ai-dialog").close();
});
byId("event-dialog").addEventListener("click", (event) => {
  if (event.target === byId("event-dialog")) byId("event-dialog").close();
});
showLogin();
updateResponseFields();
window.setInterval(refreshDashboard, 15000);

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
const state = { events: [], alerts: [], hosts: [], incidents: [], loading: false };
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
  render();
  byId("api-state").textContent = "Chưa đăng nhập";
  byId("last-updated").textContent = "Chưa đồng bộ";
  byId("change-password-button").hidden = true;
  byId("logout-button").hidden = true;
  byId("user-management-button").hidden = true;
  byId("response-management-button").hidden = true;
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

function render() {
  byId("metric-events").textContent = numberFormat.format(state.events.length);
  byId("metric-event-caption").textContent = `Trong ${state.events.length >= 500 ? "500 event mới nhất" : "các event đã tải"}`;
  byId("metric-hosts").textContent = numberFormat.format(state.hosts.length);
  renderSeverity();
  renderActivity();
  renderSources();
  renderEvents();
  renderIncidents();
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
    const [events, alerts, hosts, incidents] = await Promise.all([
      apiGet("/api/events?limit=500"),
      apiGet("/api/alerts"),
      apiGet("/api/hosts"),
      apiGet("/api/incidents"),
    ]);
    if (!apiKey || generation !== authGeneration) return;
    state.events = events;
    state.alerts = alerts;
    state.hosts = hosts;
    state.incidents = incidents;
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
byId("event-dialog").addEventListener("click", (event) => {
  if (event.target === byId("event-dialog")) byId("event-dialog").close();
});
showLogin();
updateResponseFields();
window.setInterval(refreshDashboard, 15000);

const API_BASE = window.location.protocol === "file:" ? "http://127.0.0.1:8000" : window.location.origin;
const state = { devices: [], knownDevices: [], inventoryMode: "actual", selectedIp: null, lastScan: null, gateway: null, localIp: null, subnet: null, performance: [], performanceScans: 0, alerts: [], alertTotal: 0 };
const IDLE_TIMEOUT = 5 * 60 * 1000;
let idleTimer = null;
let warningTimer = null;
let activitySentAt = 0;
let sessionActive = false;
let idleDeadline = 0;
let countdownInterval = null;
let expirationCause = "idle";
let monitorTimer = null;
let monitorEnabled = false;
let monitorBusy = false;
let monitorNextAt = null;
let operationalSettingsLoaded = false;
const $ = (selector) => document.querySelector(selector);
const elements = {
  rows: $("#device-rows"), search: $("#search-input"), filter: $("#status-filter"),
  scan: $("#scan-button"), toast: $("#toast"), dialog: $("#detail-dialog"),
};

const navigationLinks = [...document.querySelectorAll(".navigation .nav-item")];
function activateNavigationLink(link) {
  navigationLinks.forEach((item) => {
    const active = item === link;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "location");
    else item.removeAttribute("aria-current");
  });
}
navigationLinks.forEach((link) => link.addEventListener("click", () => activateNavigationLink(link)));
const initialNavigationLink = navigationLinks.find((link) => link.hash === window.location.hash);
if (initialNavigationLink) activateNavigationLink(initialNavigationLink);

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("show");
  clearTimeout(showToast.timeout);
  showToast.timeout = setTimeout(() => elements.toast.classList.remove("show"), 3300);
}

function authError(message) {
  const node = document.querySelector("#auth-error");
  if (node) node.textContent = message;
}

function renderAuthForm(mode, message = "") {
  const gate = $("#auth-gate");
  const title = $("#auth-title");
  const description = $("#auth-description");
  const stage = $("#auth-stage");
  gate.hidden = false;

  if (mode === "setup") {
    title.textContent = "Configura tu acceso";
    description.textContent = "Crea la cuenta administradora local. La clave inicial aparece en la terminal de Uvicorn.";
    stage.innerHTML = `<form class="auth-form" id="auth-form"><div class="auth-field"><label for="setup-key">Clave inicial de GearEye</label><input id="setup-key" name="setup_key" autocomplete="one-time-code" required placeholder="Pega la clave mostrada en la terminal" /></div><div class="auth-field"><label for="setup-username">Nombre de usuario</label><input id="setup-username" name="username" autocomplete="username" minlength="3" maxlength="64" required placeholder="Administrador" /></div><div class="auth-field"><label for="setup-password">Contraseña</label><input id="setup-password" name="password" type="password" autocomplete="new-password" minlength="12" required placeholder="Mínimo 12 caracteres" /></div><div class="auth-error" id="auth-error">${esc(message)}</div><button class="button button-primary auth-submit">Continuar con autenticador <span>→</span></button></form>`;
  } else if (mode === "enroll") {
    title.textContent = "Vincula tu autenticador";
    description.textContent = "En tu app autenticadora, agrega una cuenta manual con esta clave. Luego confirma el código de seis dígitos.";
    stage.innerHTML = `<div class="auth-form"><div class="auth-hint"><strong>Clave de configuración · GearEye</strong>Usa el tipo de código basado en tiempo (TOTP), con período de 30 segundos.<span class="auth-secret" id="enrollment-secret"></span></div><form class="auth-form" id="auth-form"><div class="auth-field"><label for="setup-code">Código de tu autenticador</label><input id="setup-code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" maxlength="8" required placeholder="000 000" /></div><div class="auth-error" id="auth-error">${esc(message)}</div><button class="button button-primary auth-submit">Activar protección 2FA</button></form></div>`;
    $("#enrollment-secret").textContent = state.enrollmentSecret || "";
  } else if (mode === "verify") {
    title.textContent = "Verificación en dos pasos";
    description.textContent = "Ingresa el código temporal de seis dígitos de tu aplicación autenticadora.";
    stage.innerHTML = `<form class="auth-form" id="auth-form"><div class="auth-field"><label for="login-code">Código de autenticación</label><input id="login-code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,8}" maxlength="8" required placeholder="000 000" autofocus /></div><div class="auth-error" id="auth-error">${esc(message)}</div><button class="button button-primary auth-submit">Verificar e iniciar sesión</button><div class="auth-inline"><span></span><button type="button" class="auth-secondary" id="back-to-login">Volver</button></div></form>`;
    $("#back-to-login").addEventListener("click", () => renderAuthForm("login"));
    $("#login-code").focus();
  } else {
    title.textContent = "Inicia sesión";
    description.textContent = "Accede a tu consola de red con tu cuenta GearEye.";
    stage.innerHTML = `<form class="auth-form" id="auth-form"><div class="auth-field"><label for="login-username">Nombre de usuario</label><input id="login-username" name="username" autocomplete="username" required placeholder="Tu usuario" /></div><div class="auth-field"><label for="login-password">Contraseña</label><input id="login-password" name="password" type="password" autocomplete="current-password" required placeholder="Tu contraseña" /></div><div class="auth-error" id="auth-error">${esc(message)}</div><button class="button button-primary auth-submit">Continuar <span>→</span></button></form>`;
  }
  $("#auth-form").addEventListener("submit", (event) => submitAuth(event, mode));
}

async function postAuth(path, body) {
  const url = new URL(`${API_BASE}/auth/${path}`);
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Error de autenticación (${response.status})`);
  return data;
}

async function submitAuth(event, mode) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form).entries());
  const submit = form.querySelector("button[type=submit],button:not([type])");
  submit.disabled = true;
  submit.textContent = "Verificando…";
  try {
    if (mode === "setup") {
      const result = await postAuth("setup", data);
      state.enrollmentSecret = result.secret;
      renderAuthForm("enroll");
    } else if (mode === "enroll") {
      await postAuth("confirm-setup", { code: data.code });
      state.enrollmentSecret = null;
      await checkAuth();
    } else if (mode === "login") {
      const result = await postAuth("login", data);
      state.challenge = result.challenge;
      renderAuthForm("verify");
    } else {
      await postAuth("verify", { code: data.code, challenge: state.challenge });
      state.challenge = null;
      await checkAuth();
    }
  } catch (error) {
    authError(error.message);
    submit.disabled = false;
    submit.textContent = mode === "login" ? "Continuar →" : mode === "verify" ? "Verificar e iniciar sesión" : mode === "enroll" ? "Activar protección 2FA" : "Continuar con autenticador →";
  }
}

async function checkAuth() {
  try {
    const response = await fetch(`${API_BASE}/auth/status`, { credentials: "same-origin", headers: { Accept: "application/json" } });
    const result = await response.json();
    if (!result.authenticated && sessionActive) {
      stopIdleSession();
      state.devices = [];
      state.performance = [];
      state.performanceScans = 0;
      renderSummary();
      renderDevices();
      renderPerformance();
      $("#auth-gate").hidden = true;
      $("#session-expired").hidden = false;
      return;
    }
    if (result.authenticated) {
      startIdleSession();
      $("#session-expired").hidden = true;
      $("#auth-gate").hidden = true;
      $("#top-avatar").textContent = String(result.username || "GE").slice(0, 2).toUpperCase();
      $("#profile-avatar").textContent = String(result.username || "GE").slice(0, 2).toUpperCase();
      $(".profile-copy strong").textContent = result.username;
      $("#security-status-text").textContent = "2FA activa en esta cuenta";
      setConnection(true, "Sesión protegida");
      await loadOperationalSettings();
      await scanNetwork();
      if (monitorEnabled) scheduleMonitor();
    } else if (result.configured) {
      stopIdleSession();
      renderAuthForm("login");
    } else {
      stopIdleSession();
      renderAuthForm("setup");
    }
  } catch {
    setConnection(false, "API no disponible");
    if (!sessionActive) renderAuthForm("login", "No se puede conectar con GearEye. Comprueba que Uvicorn esté activo y vuelve a cargar.");
  }
}

async function logout(reason = "manual") {
  expirationCause = reason;
  stopIdleSession();
  try {
    await fetch(`${API_BASE}/auth/logout`, { method: "POST", credentials: "same-origin" });
  } finally {
    state.devices = [];
    state.performance = [];
    state.performanceScans = 0;
    renderSummary();
    renderDevices();
    renderPerformance();
    if (reason === "manual") {
      $("#session-expired").hidden = true;
      renderAuthForm("login");
    } else {
      $("#auth-gate").hidden = true;
      $("#session-expired").hidden = false;
    }
  }
}

function stopIdleSession() {
  sessionActive = false;
  clearTimeout(monitorTimer);
  monitorNextAt = null;
  clearTimeout(idleTimer);
  clearTimeout(warningTimer);
  clearInterval(countdownInterval);
  $("#session-countdown").hidden = true;
}

function startIdleSession() {
  sessionActive = true;
  resetIdleTimers();
}

function resetIdleTimers() {
  if (!sessionActive) return;
  clearTimeout(idleTimer);
  clearTimeout(warningTimer);
  idleDeadline = Date.now() + IDLE_TIMEOUT;
  const countdown = $("#session-countdown");
  countdown.hidden = false;
  clearInterval(countdownInterval);
  const updateCountdown = () => {
    const remaining = Math.max(0, idleDeadline - Date.now());
    const seconds = Math.ceil(remaining / 1000);
    $("#session-countdown-value").textContent = `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
    countdown.classList.toggle("urgent", seconds <= 60);
  };
  updateCountdown();
  countdownInterval = setInterval(updateCountdown, 250);
  warningTimer = setTimeout(() => showToast("Tu sesión se cerrará pronto por inactividad."), IDLE_TIMEOUT - 60 * 1000);
  idleTimer = setTimeout(async () => {
    expirationCause = "idle";
    stopIdleSession();
    state.devices = [];
    state.performance = [];
    state.performanceScans = 0;
    renderSummary();
    renderDevices();
    renderPerformance();
    $("#auth-gate").hidden = true;
    $("#session-expired").hidden = false;
  }, IDLE_TIMEOUT);
}

async function reportActivity() {
  if (!sessionActive) return;
  resetIdleTimers();
  const now = Date.now();
  if (now - activitySentAt < 15_000) return;
  activitySentAt = now;
  try {
    const response = await fetch(`${API_BASE}/auth/activity`, { method: "POST", credentials: "same-origin" });
    if (response.status === 401) await checkAuth();
  } catch { /* El temporizador local sigue cerrando la sesión aunque la API no responda. */ }
}

["pointerdown", "keydown", "scroll", "touchstart"].forEach((eventName) => {
  document.addEventListener(eventName, reportActivity, { passive: true });
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) reportActivity();
});

function setConnection(online, label) {
  $("#connection-label").textContent = label;
  $(".connection").classList.toggle("online", online);
  $("#footer-api").textContent = window.location.host || "127.0.0.1:8000";
}

function deviceIcon(device) {
  if (device.tipo === "router") return "⌁";
  if (device.tipo === "impresora") return "▤";
  if (device.tipo === "computador") return "▣";
  return "◉";
}

function renderDevices() {
  const inventoryDevices = state.inventoryMode === "conocidos" ? state.knownDevices : state.devices;
  const query = elements.search.value.trim().toLowerCase();
  const status = elements.filter.value;
  const selectedType = $("#type-filter").value;
  const types = [...new Set(inventoryDevices.map((device) => device.tipo).filter(Boolean))].sort();
  $("#type-filter").innerHTML = `<option value="todos">Todos</option>${types.map((type) => `<option value="${esc(type)}">${esc(type)}</option>`).join("")}`;
  $("#type-filter").value = types.includes(selectedType) ? selectedType : "todos";
  const type = $("#type-filter").value;
  const latency = $("#latency-filter").value;
  const filtered = inventoryDevices.filter((device) => {
    const searchable = [device.ip, device.mac, device.nombre, device.fabricante, device.fabricante_red, device.modelo, device.tipo, device.responsable, device.notas].join(" ").toLowerCase();
    const latencyMatch = state.inventoryMode === "conocidos" || latency === "todos" || (latency === "sin-respuesta" ? device.estado !== "activo" : device.estado === "activo" && Number(device.tiempo_respuesta) >= Number(latency));
    return searchable.includes(query) && (status === "todos" || device.estado === status) && (type === "todos" || device.tipo === type) && latencyMatch;
  });
  if (!filtered.length) {
    elements.rows.innerHTML = `<tr><td colspan="7"><div class="empty-state"><strong>${inventoryDevices.length ? "No hay coincidencias" : state.inventoryMode === "conocidos" ? "Aún no hay equipos en el historial" : "No se encontraron dispositivos"}</strong><span>${inventoryDevices.length ? "Prueba con otro término o filtro." : state.inventoryMode === "conocidos" ? "GearEye guardará aquí los equipos cuando realices escaneos." : "Ejecuta un nuevo escaneo para consultar la red."}</span></div></td></tr>`;
  } else {
    elements.rows.innerHTML = filtered.map((device) => `
      <tr data-ip="${esc(device.ip)}" tabindex="0" aria-label="Ver detalles de ${esc(device.ip)}">
        <td><div class="device-cell"><span class="device-avatar ${esc(device.tipo)}">${deviceIcon(device)}</span><span class="device-name"><strong>${esc(device.nombre || "Dispositivo sin nombre")}</strong><span>${esc(device.modelo || device.mac || "Identificación no disponible")} · <span class="trust-label ${device.confianza === "confiable" ? "trusted" : "review"}">${device.confianza === "confiable" ? "Confiable" : "Por revisar"}</span>${device.responsable ? ` · ${esc(device.responsable)}` : ""}</span></span></div></td>
        <td class="mono">${esc(device.ip)}</td>
        <td><span class="manufacturer" title="${esc(device.fabricante || device.fabricante_red || "No identificado")}">${esc(device.fabricante || device.fabricante_red || "—")}</span></td>
        <td><span class="type-chip">${esc(device.tipo || "desconocido")}</span></td>
        <td><span class="status ${esc(device.estado)}">${esc(device.estado)}</span></td>
        <td class="latency">${state.inventoryMode === "conocidos" ? formatSeenDate(device.ultima_deteccion) : device.estado === "activo" ? `${Number(device.tiempo_respuesta).toFixed(1)} ms` : "—"}</td>
        <td><button class="row-action" aria-label="Ver detalle">›</button></td>
      </tr>`).join("");
    elements.rows.querySelectorAll("tr[data-ip]").forEach((row) => {
      row.addEventListener("click", () => openDetails(row.dataset.ip));
      row.addEventListener("keydown", (event) => { if (event.key === "Enter") openDetails(row.dataset.ip); });
    });
  }
  $("#inventory-caption").textContent = state.inventoryMode === "conocidos" ? "Equipos que GearEye detectó en escaneos anteriores; su estado corresponde a la última detección." : "Equipos encontrados en el último escaneo local";
  $("#inventory-measure-heading").textContent = state.inventoryMode === "conocidos" ? "VISTO POR ÚLTIMA VEZ" : "LATENCIA";
  $("#table-count").textContent = `${filtered.length} de ${inventoryDevices.length} dispositivos`;
}

function formatSeenDate(value) {
  if (!value) return "Sin fecha";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Sin fecha" : date.toLocaleString("es-CO", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

function renderSummary() {
  const total = state.devices.length;
  const active = state.devices.filter((device) => device.estado === "activo").length;
  const detected = state.devices.filter((device) => device.estado === "detectado").length;
  const unknown = state.devices.filter((device) => !device.fabricante || device.fabricante === "Desconocido").length;
  const responders = state.devices.filter((device) => device.estado === "activo");
  const mean = responders.length ? responders.reduce((sum, device) => sum + Number(device.tiempo_respuesta || 0), 0) / responders.length : 0;
  const score = total ? Math.round((active / total) * 100) : 0;
  $("#metric-total").textContent = total;
  $("#metric-active").textContent = active;
  $("#metric-detected").textContent = detected;
  $("#metric-latency").textContent = responders.length ? mean.toFixed(0) : "—";
  $("#nav-total").textContent = total;
  $("#health-score").textContent = `${score}%`;
  $(".score-ring").style.background = `conic-gradient(#27ba8c 0deg, #27ba8c ${score * 3.6}deg, #edf1f5 ${score * 3.6}deg)`;
  $("#health-title").textContent = total ? (score >= 80 ? "Buena respuesta" : score >= 50 ? "Respuesta parcial" : "Pocos responden") : "Sin datos";
  $("#health-caption").textContent = total ? `${active} de ${total} dispositivos responden al ping.` : "Ejecuta un escaneo para revisar la red.";
  $("#health-active").textContent = active;
  $("#health-detected").textContent = detected;
  $("#health-unknown").textContent = unknown;
  $("#last-updated").textContent = state.lastScan ? `Actualizado ${state.lastScan.toLocaleTimeString("es-CO", { hour: "2-digit", minute: "2-digit" })}` : "Sin actualizar";
}

function renderActivity() {
  const events = [...state.devices]
    .sort((a, b) => Number(b.tiempo_respuesta) - Number(a.tiempo_respuesta))
    .slice(0, 4);
  $("#activity-list").innerHTML = events.length ? events.map((device) => {
    const slow = Number(device.tiempo_respuesta) >= 150;
    const label = device.nombre || device.ip;
    const message = device.estado === "detectado" ? "Detectado sin respuesta al ping" : slow ? `Latencia elevada · ${Number(device.tiempo_respuesta).toFixed(0)} ms` : "Dispositivo activo en la red";
    return `<div class="activity-item"><span class="activity-symbol ${slow ? "warn" : ""}">${device.estado === "detectado" ? "!" : slow ? "◷" : "✓"}</span><div class="activity-text"><strong>${esc(label)}</strong> · ${esc(message)}<span class="activity-time">${esc(device.ip)} · último escaneo</span></div></div>`;
  }).join("") : `<div class="activity-empty">Los eventos de red aparecerán aquí.</div>`;
}

async function scanNetwork(background = false) {
  if (monitorBusy) return;
  monitorBusy = true;
  elements.scan.classList.add("loading");
  elements.scan.disabled = true;
  $("#scan-button-label").textContent = "Escaneando…";
  try {
    const response = await fetch(`${API_BASE}/api/dispositivos`, { credentials: "same-origin", headers: { Accept: "application/json", ...(background ? { "X-GearEye-Background": "true" } : {}) } });
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error(payload.detail || `La API respondi\u00f3 ${response.status}`);
    state.devices = Array.isArray(payload.dispositivos) ? payload.dispositivos : [];
    state.gateway = payload.puerta_enlace || null;
    state.localIp = payload.ip_local || null;
    state.subnet = payload.subred || null;
    state.lastScan = new Date();
    setConnection(true, "API conectada");
    renderSummary();
    renderDevices();
    renderTopology();
    await loadStorageStatus(background);
    await loadEvents(background);
    await loadAlerts(background);
    await loadPerformance(background);
    if (!background) showToast(`Escaneo completado: ${state.devices.length} dispositivos detectados.`);
  } catch (error) {
    setConnection(false, "API no disponible");
    showToast(error.message.includes("Failed to fetch") ? "No se pudo conectar. Abre GearEye desde http://127.0.0.1:8000/app." : error.message);
    if (!state.devices.length) elements.rows.innerHTML = `<tr><td colspan="7"><div class="empty-state"><strong>No se pudo cargar la red</strong><span>${esc(error.message)}</span></div></td></tr>`;
  } finally {
    monitorBusy = false;
    elements.scan.classList.remove("loading");
    elements.scan.disabled = false;
    $("#scan-button-label").textContent = "Escanear red";
  }
}

async function loadStorageStatus(background = false) {
  const label = $("#storage-label");
  try {
    const response = await fetch(`${API_BASE}/api/estado`, { credentials: "same-origin", headers: { Accept: "application/json", ...(background ? { "X-GearEye-Background": "true" } : {}) } });
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error("Sin conexión");
    const payload = await response.json();
    label.textContent = payload.base_datos || "Desconocida";
    label.classList.remove("storage-error");
  } catch {
    label.textContent = "No disponible";
    label.classList.add("storage-error");
  }
}

function renderTopology() {
  const router = state.devices.find((device) => device.ip === state.gateway || device.tipo === "router");
  const gatewayIp = state.gateway || router?.ip || null;
  const gateway = $("#gateway-node");
  const gatewayState = router?.estado || "sin-respuesta";
  const gatewayName = router?.nombre || (gatewayIp ? "Puerta de enlace" : "Gateway no identificado");
  gateway.className = `topology-node topology-gateway ${router ? `state-${router.estado}` : "state-unknown"}`;
  gateway.innerHTML = `<span class="topology-node-icon">?</span><span class="topology-node-copy"><strong>${esc(gatewayName)}</strong><span>${esc(gatewayIp || "IP no disponible")}</span></span><span class="topology-node-state">${router ? esc(router.estado) : "Sin respuesta"}</span>`;
  gateway.disabled = !router;
  gateway.onclick = () => router && openDetails(router.ip);

  const nodes = state.devices.filter((device) => device.ip !== gatewayIp);
  const container = $("#topology-nodes");
  $("#topology-subnet").textContent = `${state.subnet || "Subred no disponible"}${state.localIp ? ` ? Equipo local ${state.localIp}` : ""}`;
  $("#topology-total").textContent = `${nodes.length + 1} nodos`;
  container.innerHTML = nodes.length ? nodes.map((device) => `
    <button class="topology-node topology-device state-${esc(device.estado)}" type="button" data-topology-ip="${esc(device.ip)}" aria-label="Ver detalles de ${esc(device.nombre || device.ip)}">
      <span class="topology-node-icon">${device.tipo === "computador" ? "?" : device.tipo === "impresora" ? "?" : "?"}</span>
      <span class="topology-node-copy"><strong>${esc(device.nombre || device.tipo || "Dispositivo")}</strong><span>${esc(device.ip)} ? ${esc(device.fabricante || device.fabricante_red || "Fabricante desconocido")}</span></span>
      <span class="topology-node-state">${esc(device.estado)}</span>
    </button>`).join("") : '<div class="topology-empty">Ejecuta un escaneo para mostrar los dispositivos de esta red.</div>';
  container.querySelectorAll("[data-topology-ip]").forEach((button) => button.addEventListener("click", () => openDetails(button.dataset.topologyIp)));
  requestAnimationFrame(drawTopologyLinks);
}

function drawTopologyLinks() {
  const canvas = $("#topology-canvas");
  const svg = $("#topology-links");
  const root = $("#gateway-node");
  const children = [...$("#topology-nodes").querySelectorAll("[data-topology-ip]")];
  const bounds = canvas.getBoundingClientRect();
  const width = Math.max(1, canvas.clientWidth);
  const height = Math.max(1, canvas.scrollHeight);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", width);
  svg.setAttribute("height", height);
  svg.replaceChildren();
  if (!state.devices.length || !root.offsetHeight) return;

  const rootBox = root.getBoundingClientRect();
  const x1 = rootBox.left + rootBox.width / 2 - bounds.left;
  const y1 = rootBox.bottom - bounds.top;
  const namespace = "http://www.w3.org/2000/svg";
  children.forEach((node) => {
    const box = node.getBoundingClientRect();
    const x2 = box.left + box.width / 2 - bounds.left;
    const y2 = box.top - bounds.top;
    const path = document.createElementNS(namespace, "path");
    path.setAttribute("d", `M ${x1} ${y1} C ${x1} ${y1 + 48}, ${x2} ${y2 - 42}, ${x2} ${y2}`);
    path.setAttribute("class", `topology-edge ${node.classList.contains("state-activo") ? "edge-active" : "edge-detected"}`);
    svg.append(path);
  });
}

function updateMonitorControls() {
  $("#monitor-state").textContent = monitorEnabled ? "Monitoreo autom\u00e1tico activo" : "Monitoreo pausado";
  const nextTime = monitorNextAt ? ` · siguiente ${monitorNextAt.toLocaleTimeString("es-CO", { hour: "2-digit", minute: "2-digit" })}` : "";
  $("#monitor-caption").textContent = monitorEnabled ? `Cada ${$("#scan-interval").value} min${nextTime}` : "Escaneo manual";
  $("#monitor-toggle").textContent = monitorEnabled ? "Pausar monitoreo" : "Activar monitoreo";
  $("#monitor-indicator").classList.toggle("active", monitorEnabled);
}

function scheduleMonitor() {
  clearTimeout(monitorTimer);
  if (!monitorEnabled || !sessionActive) { monitorNextAt = null; updateMonitorControls(); return; }
  monitorNextAt = new Date(Date.now() + Number($("#scan-interval").value) * 60_000);
  updateMonitorControls();
  monitorTimer = setTimeout(async () => {
    if (monitorEnabled && sessionActive) await scanNetwork(true);
    scheduleMonitor();
  }, Number($("#scan-interval").value) * 60_000);
}

async function loadOperationalSettings() {
  try {
    const response = await fetch(`${API_BASE}/api/configuracion/monitoreo`, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error("No se pudo cargar la configuración operativa.");
    const config = await response.json();
    $("#scan-interval").value = String(config.intervalo_minutos);
    $("#latency-threshold").value = String(config.umbral_latencia_ms);
    $("#alert-new-devices").checked = Boolean(config.alertar_dispositivo_nuevo);
    $("#alert-offline-devices").checked = Boolean(config.alertar_dispositivo_ausente);
    monitorEnabled = Boolean(config.monitoreo_activo);
    operationalSettingsLoaded = true;
    updateMonitorControls();
  } catch (error) {
    console.warn(error);
  }
}

async function saveOperationalSettings(showConfirmation = true) {
  const button = $("#save-alert-settings");
  if (button) button.disabled = true;
  const payload = {
    monitoreo_activo: monitorEnabled,
    intervalo_minutos: Number($("#scan-interval").value),
    umbral_latencia_ms: Number($("#latency-threshold").value),
    alertar_dispositivo_nuevo: $("#alert-new-devices").checked,
    alertar_dispositivo_ausente: $("#alert-offline-devices").checked,
  };
  try {
    const response = await fetch(`${API_BASE}/api/configuracion/monitoreo`, {
      method: "PUT", credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error(result.detail || "No se pudo guardar la configuración.");
    operationalSettingsLoaded = true;
    if (showConfirmation) showToast("Configuración de monitoreo guardada.");
  } catch (error) { showToast(error.message); }
  finally { if (button) button.disabled = false; }
}

async function exportEvents() {
  const days = Number($("#events-period").value);
  try {
    const response = await fetch(`${API_BASE}/api/eventos.csv?dias=${days}`, { credentials: "same-origin" });
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || "No se pudo descargar la bitácora.");
    }
    const blob = await response.blob();
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.href = url;
    link.download = `geareye-bitacora-${days}-dias-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
    showToast("Bitácora de red descargada.");
  } catch (error) { showToast(error.message); }
}

async function loadEvents(background = false) {
  try {
    const response = await fetch(`${API_BASE}/api/eventos?limite=30`, { credentials: "same-origin", headers: { Accept: "application/json", ...(background ? { "X-GearEye-Background": "true" } : {}) } });
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error("No se pudo consultar la bit\u00e1cora.");
    const payload = await response.json();
    const events = payload.eventos || [];
    $("#activity-list").innerHTML = events.length ? events.slice(0, 8).map((event) => {
      const icon = event.tipo === "dispositivo_nuevo" ? "+" : event.estado_actual === "inactivo" ? "!" : "\u2194";
      const tone = event.estado_actual === "inactivo" ? "warn" : "";
      const name = event.nombre || event.ip;
      const date = new Date(event.fecha).toLocaleString("es-CO", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
      return `<div class="activity-item"><span class="activity-symbol ${tone}">${icon}</span><div class="activity-text"><strong>${esc(name)}</strong> \u00b7 ${esc(event.mensaje)}<span class="activity-time">${esc(event.ip)} \u00b7 ${esc(date)}</span></div></div>`;
    }).join("") : '<div class="activity-empty">Sin cambios registrados. El primer escaneo de referencia no genera alertas.</div>';
  } catch (error) {
    $("#activity-list").innerHTML = `<div class="activity-empty">${esc(error.message)}</div>`;
  }
}

async function loadAlerts(background = false) {
  try {
    const response = await fetch(`${API_BASE}/api/alertas?limite=30`, { credentials: "same-origin", headers: { Accept: "application/json", ...(background ? { "X-GearEye-Background": "true" } : {}) } });
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error("No se pudieron consultar las alertas.");
    const payload = await response.json();
    state.alerts = payload.alertas || [];
    state.alertTotal = Number(payload.total ?? state.alerts.length);
    renderAlerts();
  } catch (error) {
    $("#alert-list").innerHTML = `<div class="alert-empty">${esc(error.message)}</div>`;
  }
}

function renderAlerts() {
  const alerts = state.alerts;
  $("#nav-alerts").textContent = state.alertTotal > 99 ? "99+" : state.alertTotal;
  $("#alert-count").textContent = `${state.alertTotal} pendiente${state.alertTotal === 1 ? "" : "s"}`;
  $("#alert-count").classList.toggle("has-critical", alerts.some((item) => item.severidad === "critica"));
  $("#alert-list").innerHTML = alerts.length ? alerts.slice(0, 8).map((alert) => {
    const date = new Date(alert.fecha).toLocaleString("es-CO", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
    const title = alert.nombre || alert.ip;
    const label = alert.tipo === "latencia_elevada" ? "Latencia elevada" : alert.tipo === "dispositivo_nuevo" ? "Equipo nuevo" : alert.estado_actual === "inactivo" ? "Conectividad" : "Cambio de estado";
    return `<article class="alert-item severity-${esc(alert.severidad)}"><span class="alert-mark">${alert.severidad === "critica" ? "!" : alert.severidad === "advertencia" ? "+" : "i"}</span><div class="alert-copy"><strong>${esc(title)}</strong><span>${esc(alert.mensaje)}</span><small>${esc(alert.ip)} · ${esc(date)} · ${label}</small></div><button class="alert-ack" type="button" data-ack-alert="${Number(alert.id)}">Reconocer</button></article>`;
  }).join("") : '<div class="alert-empty"><strong>Todo al día</strong><span>No hay cambios de red pendientes de revisión.</span></div>';
  $("#alert-list").querySelectorAll("[data-ack-alert]").forEach((button) => button.addEventListener("click", () => acknowledgeAlert(button.dataset.ackAlert)));
}

async function acknowledgeAlert(id) {
  try {
    const response = await fetch(`${API_BASE}/api/alertas/${encodeURIComponent(id)}/reconocer`, { method: "POST", credentials: "same-origin", headers: { Accept: "application/json" } });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || "No se pudo reconocer la alerta.");
    await loadAlerts();
    showToast("Alerta reconocida.");
  } catch (error) { showToast(error.message); }
}

function renderPerformance() {
  const query = $("#performance-search").value.trim().toLowerCase();
  const rows = state.performance.filter((item) =>
    [item.ip, item.mac, item.nombre, item.fabricante, item.fabricante_red, item.modelo, item.tipo]
      .join(" ").toLowerCase().includes(query));
  const averages = state.performance.filter((item) => item.disponibilidad_pct !== null && item.disponibilidad_pct !== undefined);
  const meanAvailability = averages.length
    ? averages.reduce((sum, item) => sum + Number(item.disponibilidad_pct), 0) / averages.length
    : null;
  const latencyValues = state.performance.map((item) => item.latencia_media_ms).filter((value) => value !== null && value !== undefined).map(Number);
  const meanLatency = latencyValues.length ? latencyValues.reduce((sum, value) => sum + value, 0) / latencyValues.length : null;

  $("#performance-scans").textContent = state.performanceScans || "0";
  $("#performance-devices").textContent = state.performance.length;
  $("#performance-availability").textContent = meanAvailability === null ? "—" : `${meanAvailability.toFixed(1)}%`;
  $("#performance-latency").innerHTML = meanLatency === null ? "—" : `${meanLatency.toFixed(1)} <small>ms</small>`;
  $("#glance-availability").textContent = meanAvailability === null ? "—" : `${meanAvailability.toFixed(1)}%`;
  $("#glance-latency").textContent = meanLatency === null ? "—" : `${meanLatency.toFixed(1)} ms`;
  $("#glance-scans").textContent = state.performanceScans || "0";
  $("#performance-count").textContent = `${rows.length} de ${state.performance.length} dispositivos`;

  if (!rows.length) {
    const message = state.performance.length ? "No hay coincidencias para ese filtro." : "Todavía no hay escaneos en el periodo seleccionado.";
    $("#performance-rows").innerHTML = `<tr><td colspan="7"><div class="empty-state"><strong>Sin métricas disponibles</strong><span>${esc(message)}</span></div></td></tr>`;
    return;
  }

  $("#performance-rows").innerHTML = rows.map((item) => {
    const availability = item.disponibilidad_pct === null || item.disponibilidad_pct === undefined ? null : Number(item.disponibilidad_pct);
    const barWidth = availability === null ? 0 : Math.max(0, Math.min(100, availability));
    const availabilityText = availability === null ? "—" : `${availability.toFixed(1)}%`;
    const latency = (value) => value === null || value === undefined ? "—" : `${Number(value).toFixed(1)} ms`;
    const title = item.nombre || item.tipo || "Dispositivo";
    const detail = item.fabricante || item.fabricante_red || item.mac || item.ip;
    return `<tr>
      <td><div class="device-cell"><span class="device-avatar ${esc(item.tipo || "desconocido")}">${deviceIcon({ tipo: item.tipo })}</span><span class="device-name"><strong>${esc(title)}</strong><span>${esc(detail)} · ${esc(item.ip)}</span></span></div></td>
      <td><span class="status ${esc(item.estado_actual || "inactivo")}">${esc(item.estado_actual || "Sin datos")}</span></td>
      <td><div class="performance-availability"><strong>${availabilityText}</strong><span class="performance-meter"><i style="width:${barWidth}%"></i></span></div></td>
      <td>${Number(item.escaneos_con_respuesta || 0)} / ${Number(item.escaneos_registrados || 0)}</td>
      <td>${latency(item.latencia_media_ms)}</td><td>${latency(item.latencia_minima_ms)}</td><td>${latency(item.latencia_maxima_ms)}</td>
    </tr>`;
  }).join("");
}

async function loadPerformance(background = false) {
  const days = $("#performance-period").value;
  $("#performance-rows").innerHTML = '<tr><td colspan="7"><div class="empty-state"><span class="loader"></span><strong>Consultando historial</strong><span>Un momento, por favor.</span></div></td></tr>';
  try {
    const response = await fetch(`${API_BASE}/api/informes?dias=${encodeURIComponent(days)}`, {
      credentials: "same-origin",
      headers: { Accept: "application/json", ...(background ? { "X-GearEye-Background": "true" } : {}) },
    });
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error(payload.detail || `La API respondió ${response.status}`);
    state.performance = payload.resumen_dispositivos || [];
    state.performanceScans = Number(payload.escaneos_completados || 0);
    renderPerformance();
  } catch (error) {
    $("#performance-count").textContent = "No disponible";
    $("#performance-rows").innerHTML = `<tr><td colspan="7"><div class="empty-state"><strong>No se pudo cargar el rendimiento</strong><span>${esc(error.message)}</span></div></td></tr>`;
  }
}

function detailFields(device) {
  return [
    ["Dirección IP", device.ip], ["Dirección MAC", device.mac], ["Nombre de host", device.nombre],
    ["Fabricante", device.fabricante], ["Fabricante de red", device.fabricante_red], ["Modelo", device.modelo],
    ["Tipo", device.tipo], ["Estado", device.estado], ["Inventario", device.confianza === "confiable" ? "Confiable" : "Por revisar"], ["Responsable", device.responsable], ["Latencia observada", device.estado === "activo" ? `${Number(device.tiempo_respuesta).toFixed(2)} ms` : "Sin respuesta al ping"],
  ];
}

function formatHistoryDate(value, includeDate = false) {
  const date = new Date(value);
  return date.toLocaleString("es-CO", includeDate
    ? { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }
    : { hour: "2-digit", minute: "2-digit" });
}

async function loadHistory(ip) {
  const chart = $("#latency-chart");
  const summary = $("#history-summary");
  $("#history-count").textContent = "Cargando…";
  chart.innerHTML = '<div class="history-empty"><span class="loader"></span> Consultando historial</div>';
  summary.innerHTML = "";
  try {
    const response = await fetch(`${API_BASE}/api/historial/${encodeURIComponent(ip)}?limite=30`, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error(payload.detail || `La API respondió ${response.status}`);

    const scans = payload.mediciones || [];
    const points = scans.filter((item) => item.latencia_ms !== null && item.latencia_ms !== undefined && Number.isFinite(Number(item.latencia_ms)));
    $("#history-count").textContent = `${points.length} respuestas · ${scans.length} escaneos`;
    if (!points.length) {
      chart.innerHTML = `<div class="history-empty">${scans.length ? "Hay escaneos, pero este equipo no respondió al ping." : "Aún no hay mediciones guardadas. Ejecuta un escaneo de red para empezar."}</div>`;
      const latest = scans.at(-1);
      const details = latest ? [latest.nombre, latest.fabricante || latest.fabricante_red, latest.modelo, latest.tipo].filter(Boolean).join(" ? ") : "";
      summary.innerHTML = `${details ? `<span class="history-device-info">${esc(details)}</span>` : ""}<span class="history-retention">Se conserva durante ${payload.dias_retencion} d?as.</span>`;
      return;
    }

    const values = points.map((item) => Number(item.latencia_ms));
    const low = Math.min(...values);
    const high = Math.max(...values);
    const ceiling = high === low ? high + Math.max(10, high * 0.15) : high * 1.15;
    const left = 35;
    const right = 610;
    const top = 15;
    const bottom = 132;
    const coords = values.map((value, index) => {
      const x = points.length === 1 ? (left + right) / 2 : left + (index / (points.length - 1)) * (right - left);
      const y = bottom - (value / ceiling) * (bottom - top);
      return { x, y, value, item: points[index] };
    });
    const line = coords.map((point, index) => `${index ? "L" : "M"} ${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(" ");
    const area = `${line} L ${coords.at(-1).x.toFixed(1)} ${bottom} L ${coords[0].x.toFixed(1)} ${bottom} Z`;
    const grids = [0, 1, 2].map((index) => {
      const y = top + index * ((bottom - top) / 2);
      const value = ceiling * (1 - index / 2);
      return `<line x1="${left}" y1="${y}" x2="${right}" y2="${y}" class="chart-grid"/><text x="${left - 8}" y="${y + 3}" class="chart-axis" text-anchor="end">${value.toFixed(0)}</text>`;
    }).join("");
    const dots = coords.map(({ x, y, value, item }) => {
      const title = `${formatHistoryDate(item.fecha, true)} · ${value.toFixed(1)} ms`;
      return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.5" class="chart-point"><title>${esc(title)}</title></circle>`;
    }).join("");
    const firstDate = esc(formatHistoryDate(points[0].fecha, true));
    const lastDate = esc(formatHistoryDate(points.at(-1).fecha, true));
    chart.innerHTML = `<svg viewBox="0 0 640 165" role="img" aria-label="Historial de latencia para ${esc(ip)}">${grids}<path d="${area}" class="chart-area"/><path d="${line}" class="chart-line" pathLength="1000"/>${dots}<text x="${left}" y="156" class="chart-date">${firstDate}</text><text x="${right}" y="156" text-anchor="end" class="chart-date">${lastDate}</text></svg>`;

    const average = values.reduce((sum, value) => sum + value, 0) / values.length;
    const latest = scans.at(-1);
    const details = latest ? [latest.nombre, latest.fabricante || latest.fabricante_red, latest.modelo, latest.tipo].filter(Boolean).join(" ? ") : "";
    summary.innerHTML = `<div><span>Media</span><strong>${average.toFixed(1)} <small>ms</small></strong></div><div><span>M?nima</span><strong>${low.toFixed(1)} <small>ms</small></strong></div><div><span>M?xima</span><strong>${high.toFixed(1)} <small>ms</small></strong></div><span class="history-device-info">${esc(details || ip)}</span><span class="history-retention">Retenci?n: ${payload.dias_retencion} d?as</span>`;
  } catch (error) {
    $("#history-count").textContent = "No disponible";
    chart.innerHTML = `<div class="history-empty">No se pudo cargar el historial: ${esc(error.message)}</div>`;
  }
}

async function loadDiagnostic(ip) {
  $("#diagnostic-content").textContent = "Consultando diagnóstico…";
  try {
    const response = await fetch(`${API_BASE}/api/diagnostico/${encodeURIComponent(ip)}`, { credentials: "same-origin", headers: { Accept: "application/json" } });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || `La API respondió ${response.status}`);
    const d = payload.diagnostico;
    $("#diagnostic-content").innerHTML = `<span class="diagnostic-level">${esc(d.nivel)}</span><p><strong>${esc(d.mensaje)}</strong></p><p>${esc(d.recomendacion)}</p><p>${esc(d.observaciones || "")}</p>`;
  } catch (error) {
    $("#diagnostic-content").textContent = `No se pudo obtener el diagnóstico: ${error.message}`;
  }
}

function openDetails(ip) {
  const device = state.devices.find((item) => item.ip === ip);
  if (!device) return;
  state.selectedIp = ip;
  $("#detail-title").textContent = device.nombre || device.ip;
  $("#detail-status").innerHTML = `<span class="status ${esc(device.estado)}">${esc(device.estado)}</span>`;
  $("#detail-grid").innerHTML = detailFields(device).map(([label, value]) => `<div class="detail-item"><span>${esc(label)}</span><strong>${esc(value || "No disponible")}</strong></div>`).join("");
  renderTrustControl(device);
  loadDeviceNotes(ip);
  $("#advanced-results").textContent = "Estas comprobaciones solo se ejecutan cuando las solicitas.";
  elements.dialog.showModal();
  loadHistory(ip);
  loadDiagnostic(ip);
}

async function loadDeviceNotes(ip) {
  $("#device-owner").value = "";
  $("#device-notes").value = "";
  try {
    const response = await fetch(`${API_BASE}/api/dispositivos/${encodeURIComponent(ip)}/notas`, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!response.ok) return;
    const data = await response.json();
    if (state.selectedIp !== ip) return;
    $("#device-owner").value = data.responsable || "";
    $("#device-notes").value = data.notas || "";
  } catch { /* Notes are optional operational metadata. */ }
}

async function saveDeviceNotes() {
  const ip = state.selectedIp;
  if (!ip) return;
  const button = $("#save-device-notes");
  button.disabled = true;
  try {
    const response = await fetch(`${API_BASE}/api/dispositivos/${encodeURIComponent(ip)}/notas`, {
      method: "PUT", credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ responsable: $("#device-owner").value, notas: $("#device-notes").value }),
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error(data.detail || "No se pudieron guardar los datos del equipo.");
    const device = state.devices.find((item) => item.ip === ip);
    if (device) {
      device.responsable = data.responsable;
      device.notas = data.notas;
      renderDevices();
      $("#detail-grid").innerHTML = detailFields(device).map(([label, value]) => `<div class="detail-item"><span>${esc(label)}</span><strong>${esc(value || "No disponible")}</strong></div>`).join("");
    }
    showToast("Responsable y notas guardados.");
  } catch (error) { showToast(error.message); }
  finally { button.disabled = false; }
}

async function runAdvancedDiagnostics() {
  if (!state.selectedIp) return;
  const button = $("#advanced-run");
  const results = $("#advanced-results");
  button.disabled = true;
  button.textContent = "Analizando…";
  results.textContent = "Ejecutando comprobaciones locales…";
  try {
    const response = await fetch(`${API_BASE}/api/diagnostico-avanzado/${encodeURIComponent(state.selectedIp)}`, {
      method: "POST", credentials: "same-origin", headers: { Accept: "application/json" },
    });
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error(payload.detail || "No se pudo ejecutar el diagnóstico avanzado.");
    const ping = payload.ping || {};
    const average = ping.latencia_media_ms === null || ping.latencia_media_ms === undefined ? "sin respuesta" : `${Number(ping.latencia_media_ms).toFixed(1)} ms de media`;
    const ports = (payload.puertos_abiertos || []).map((item) => `${esc(item.servicio)} (${Number(item.puerto)})`).join(", ") || "No se detectaron puertos abiertos en la muestra.";
    const hops = payload.trazado?.saltos || [];
    const trace = hops.length ? `<ol>${hops.map((hop) => `<li>${esc(hop)}</li>`).join("")}</ol>` : `<span>${payload.trazado?.error ? esc(payload.trazado.error) : "La ruta no respondió o el sistema no tiene tracert disponible."}</span>`;
    results.innerHTML = `<div class="advanced-result-grid"><div><strong>ICMP</strong><span>${Number(ping.recibidos || 0)} / ${Number(ping.enviados || 5)} respuestas · ${Number(ping.perdida_pct ?? 100)}% de pérdida · ${average}</span></div><div><strong>Puertos TCP</strong><span>${ports}</span></div><div class="advanced-trace"><strong>Ruta (máximo 12 saltos)</strong>${trace}</div></div><small>${esc(payload.nota || "")}</small>`;
  } catch (error) {
    results.textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Ejecutar pruebas";
  }
}

function renderTrustControl(device) {
  const trusted = device.confianza === "confiable";
  $("#trust-control").innerHTML = `<div><strong>${trusted ? "Equipo revisado" : "Equipo pendiente de revisión"}</strong><span>${trusted ? "Su IP y MAC coinciden con el inventario confiable local." : "Confirma este equipo si reconoces que pertenece a tu red."}</span></div><button class="button ${trusted ? "button-secondary" : "button-primary"}" id="trust-toggle">${trusted ? "Quitar confianza" : "Marcar como confiable"}</button>`;
  $("#trust-toggle").addEventListener("click", () => updateTrust(device.ip, !trusted));
}

async function updateTrust(ip, confiable) {
  const button = $("#trust-toggle");
  button.disabled = true;
  try {
    const response = await fetch(`${API_BASE}/api/dispositivos/${encodeURIComponent(ip)}/confianza`, {
      method: "PUT", credentials: "same-origin", headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ confiable }),
    });
    const payload = await response.json().catch(() => ({}));
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) throw new Error(payload.detail || "No se pudo actualizar el inventario confiable.");
    const device = state.devices.find((item) => item.ip === ip);
    if (device) device.confianza = confiable ? "confiable" : "por_revisar";
    renderDevices();
    if (device) {
      $("#detail-grid").innerHTML = detailFields(device).map(([label, value]) => `<div class="detail-item"><span>${esc(label)}</span><strong>${esc(value || "No disponible")}</strong></div>`).join("");
      renderTrustControl(device);
    }
    showToast(confiable ? "Equipo añadido al inventario confiable." : "Equipo marcado para revisión.");
  } catch (error) {
    button.disabled = false;
    showToast(error.message);
  }
}

function exportCsv() {
  if (!state.devices.length) return showToast("No hay dispositivos para exportar.");
  const columns = ["ip", "mac", "nombre", "fabricante", "fabricante_red", "modelo", "tipo", "estado", "confianza", "tiempo_respuesta"];
  const csv = [columns.join(","), ...state.devices.map((device) => columns.map((key) => `"${String(device[key] ?? "").replaceAll('"', '""')}"`).join(","))].join("\r\n");
  const url = URL.createObjectURL(new Blob(["\ufeff", csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `geareye-dispositivos-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
}

async function downloadReport() {
  const button = $("#report-button");
  const days = $("#report-period").value;
  button.disabled = true;
  button.classList.add("loading");
  try {
    const response = await fetch(`${API_BASE}/api/informes.csv?dias=${encodeURIComponent(days)}`, {
      credentials: "same-origin",
      headers: { Accept: "text/csv" },
    });
    if (response.status === 401) { await checkAuth(); return; }
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || `La API respondió ${response.status}`);
    }
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || `geareye-informe-${days}-dias.csv`;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast("Informe descargado con inventario, latencias y bitácora.");
  } catch (error) {
    showToast(error.message || "No se pudo generar el informe.");
  } finally {
    button.disabled = false;
    button.classList.remove("loading");
  }
}

elements.scan.addEventListener("click", scanNetwork);
$("#monitor-toggle").addEventListener("click", async () => {
  monitorEnabled = !monitorEnabled;
  updateMonitorControls();
  if (monitorEnabled) {
    await saveOperationalSettings(false);
    await scanNetwork();
    scheduleMonitor();
  } else {
    clearTimeout(monitorTimer);
    monitorNextAt = null;
    updateMonitorControls();
    await saveOperationalSettings(false);
  }
});
$("#scan-interval").addEventListener("change", async () => {
  updateMonitorControls();
  if (monitorEnabled) scheduleMonitor();
  await saveOperationalSettings(false);
});
$("#save-alert-settings").addEventListener("click", () => saveOperationalSettings());
$("#events-export").addEventListener("click", exportEvents);
$("#save-device-notes").addEventListener("click", saveDeviceNotes);
$("#events-reload").addEventListener("click", loadEvents);
$("#alerts-reload").addEventListener("click", () => loadAlerts());
$("#performance-reload").addEventListener("click", () => loadPerformance());
$("#performance-period").addEventListener("change", () => loadPerformance());
$("#performance-search").addEventListener("input", renderPerformance);
window.addEventListener("resize", drawTopologyLinks);
elements.search.addEventListener("input", renderDevices);
elements.filter.addEventListener("change", renderDevices);
$("#type-filter").addEventListener("change", renderDevices);
$("#latency-filter").addEventListener("change", renderDevices);
$("#export-button").addEventListener("click", exportCsv);
$("#report-button").addEventListener("click", downloadReport);
$("#detail-refresh").addEventListener("click", () => {
  if (state.selectedIp) {
    loadDiagnostic(state.selectedIp);
    loadHistory(state.selectedIp);
  }
});
$("#history-reload").addEventListener("click", () => state.selectedIp && loadHistory(state.selectedIp));
$("#advanced-run").addEventListener("click", runAdvancedDiagnostics);
document.querySelectorAll(".close-dialog").forEach((button) => button.addEventListener("click", () => elements.dialog.close()));
elements.dialog.addEventListener("click", (event) => { if (event.target === elements.dialog) elements.dialog.close(); });
$("#logout-button").addEventListener("click", () => logout("manual"));
$("#expired-return").addEventListener("click", () => {
  $("#session-expired").hidden = true;
  renderAuthForm("login");
});
checkAuth();

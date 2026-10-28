const API_BASE = window.location.protocol === "file:" ? "http://127.0.0.1:8000" : window.location.origin;
const DAY = 24 * 60 * 60 * 1000;
const inventory = { devices: [], type: "todos", selected: null, role: null, networks: [] };
const $ = (selector) => document.querySelector(selector);

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(showToast.timeout);
  showToast.timeout = setTimeout(() => toast.classList.remove("show"), 3300);
}

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "same-origin",
    ...options,
    headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) },
  });
  if (response.status === 401) {
    window.location.href = "/app/";
    throw new Error("La sesión terminó. Inicia sesión de nuevo.");
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `La API respondió ${response.status}`);
  return payload;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("es-CO", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function vendorOf(device) {
  return device.fabricante || device.fabricante_red || "Fabricante no identificado";
}

function networkOf(device) {
  return inventory.networks.find((red) => red.id === device.red_id);
}

function networkLabel(device) {
  const red = networkOf(device);
  return red ? `${red.nombre} (${red.subred})` : (device.subredes || [device.subred]).filter(Boolean).join(", ");
}

const deviceKey = (device) => `${device.red_id ?? ""}|${device.ip}`;

function ipKey(ip) {
  return String(ip || "").split(".").reduce((total, part) => total * 256 + Number(part || 0), 0);
}

function filteredDevices() {
  const query = $("#inv-search").value.trim().toLowerCase();
  const state = $("#inv-state").value;
  const trust = $("#inv-trust").value;
  const seen = $("#inv-seen").value;
  const now = Date.now();
  const rows = inventory.devices.filter((device) => {
    const searchable = [displayName(device), ...(device.ips || [device.ip]), device.mac, device.fabricante, device.fabricante_red,
      device.modelo, typeLabel(device.tipo), device.sistema, device.responsable, device.notas, networkOf(device)?.nombre].join(" ").toLowerCase();
    const age = now - new Date(device.ultima_deteccion || 0).getTime();
    const seenMatch = seen === "todos" || (seen === "viejo" ? age > 7 * DAY : age <= Number(seen) * DAY);
    return searchable.includes(query)
      && (inventory.type === "todos" || device.tipo === inventory.type)
      && (state === "todos" || device.estado === state)
      && (trust === "todos" || device.confianza === trust)
      && seenMatch;
  });
  const sorters = {
    reciente: (a, b) => String(b.ultima_deteccion).localeCompare(String(a.ultima_deteccion)),
    antiguo: (a, b) => String(a.primera_deteccion).localeCompare(String(b.primera_deteccion)),
    nombre: (a, b) => displayName(a).localeCompare(displayName(b), "es"),
    ip: (a, b) => ipKey(a.ip) - ipKey(b.ip),
    tipo: (a, b) => typeLabel(a.tipo).localeCompare(typeLabel(b.tipo), "es") || displayName(a).localeCompare(displayName(b), "es"),
  };
  return rows.sort(sorters[$("#inv-sort").value]);
}

function renderOverview() {
  const devices = inventory.devices;
  const counts = devices.reduce((acc, device) => ({ ...acc, [device.tipo || "desconocido"]: (acc[device.tipo || "desconocido"] || 0) + 1 }), {});
  const types = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  const chip = (type, label, count) => `<button class="type-filter${inventory.type === type ? " active" : ""}" type="button" data-type="${esc(type)}" aria-pressed="${inventory.type === type}">${type === "todos" ? "" : icon(ICON_PATHS[type] ? type : "desconocido")}<span>${esc(label)}</span><b>${count}</b></button>`;
  $("#type-chips").innerHTML = chip("todos", "Todos", devices.length) + types.map((type) => chip(type, typeLabel(type), counts[type])).join("");
  $("#type-chips").querySelectorAll("[data-type]").forEach((button) => button.addEventListener("click", () => {
    inventory.type = button.dataset.type;
    renderOverview();
    renderRows();
  }));
  const now = Date.now();
  const recent = devices.filter((device) => now - new Date(device.ultima_deteccion || 0).getTime() <= DAY).length;
  const review = devices.filter((device) => device.confianza !== "confiable").length;
  const unknown = devices.filter((device) => !device.tipo || device.tipo === "desconocido").length;
  const active = devices.filter((device) => device.estado === "activo").length;
  $("#inventory-facts").innerHTML = [
    ["Responden ahora", active],
    ["Vistos en 24 horas", recent],
    ["Por revisar", review],
    ["Sin clasificar", unknown],
  ].map(([label, value]) => `<div><dt>${label}</dt><dd>${value}</dd></div>`).join("");
  $("#nav-inventory").textContent = devices.length;
}

function renderRows() {
  const rows = filteredDevices();
  $("#inventory-count").textContent = `${rows.length} de ${inventory.devices.length} equipos`;
  if (!rows.length) {
    $("#inventory-rows").innerHTML = `<tr><td colspan="8"><div class="empty-state"><strong>${inventory.devices.length ? "No hay equipos con esos filtros" : "El inventario está vacío"}</strong><span>${inventory.devices.length ? "Cambia la búsqueda o los filtros." : "Ejecuta un escaneo desde el panel para registrar los equipos de la red."}</span></div></td></tr>`;
    return;
  }
  const showNetwork = !$("#inv-network").value && inventory.networks.length > 1;
  $("#inventory-rows").innerHTML = rows.map((device) => `
    <tr data-key="${esc(deviceKey(device))}" tabindex="0" aria-label="Ver ficha de ${esc(displayName(device))}">
      <td><div class="device-cell"><span class="device-avatar ${esc(device.tipo)}">${deviceIcon(device)}</span><span class="device-name"><strong title="${esc(displayName(device))}">${esc(displayName(device))}</strong><span>${esc(vendorOf(device))}${device.mac ? ` · ${esc(device.mac)}` : ""}</span><span class="mobile-meta">${esc((device.ips || [device.ip]).join(", "))} · ${esc(typeLabel(device.tipo))} · <b class="meta-state ${esc(device.estado)}">${esc(capitalize(device.estado))}</b> · ${esc(relativeSeen(device.ultima_deteccion))}</span></span></div></td>
      <td class="mono">${esc((device.ips || [device.ip]).join(", "))}${showNetwork ? `<span class="cell-sub">${esc(networkOf(device)?.nombre || "Red sin identificar")}</span>` : ""}</td>
      <td><span class="type-chip">${esc(typeLabel(device.tipo))}</span></td>
      <td class="system-cell">${esc(device.sistema || "—")}</td>
      <td><span class="status ${esc(device.estado)}">${esc(device.estado)}</span></td>
      <td><span class="trust-pill ${device.confianza === "confiable" ? "trusted" : "review"}">${device.confianza === "confiable" ? "Confiable" : "Por revisar"}</span></td>
      <td>${esc(device.responsable || "—")}</td>
      <td class="date-cell"><span title="${esc(formatDate(device.ultima_deteccion))}">${esc(relativeSeen(device.ultima_deteccion))}</span></td>
    </tr>`).join("");
  $("#inventory-rows").querySelectorAll("tr[data-key]").forEach((row) => {
    row.addEventListener("click", () => openDrawer(row.dataset.key));
    row.addEventListener("keydown", (event) => { if (event.key === "Enter") openDrawer(row.dataset.key); });
  });
}

function openDrawer(key) {
  const device = inventory.devices.find((item) => deviceKey(item) === key) || inventory.devices.find((item) => item.ip === key);
  if (!device) return;
  inventory.selected = device;
  $("#drawer-icon").className = `device-avatar ${device.tipo}`;
  $("#drawer-icon").innerHTML = deviceIcon(device);
  $("#drawer-title").textContent = displayName(device);
  $("#drawer-status").innerHTML = `<span class="status ${esc(device.estado)}">${esc(device.estado)}</span>`;
  const fields = [
    [(device.ips || []).length > 1 ? "Direcciones IP" : "Dirección IP", (device.ips || [device.ip]).join(", ")],
    ["Dirección MAC", device.mac], ["Nombre de host", device.nombre], ["Tipo", typeLabel(device.tipo)],
    ["Sistema estimado", device.sistema], ["Fabricante", device.fabricante], ["Fabricante de red", device.fabricante_red],
    ["Modelo", device.modelo], ["Red", networkLabel(device)],
    ["Primera detección", formatDate(device.primera_deteccion)], ["Última detección", formatDate(device.ultima_deteccion)],
    ["Última latencia", device.estado === "activo" && device.tiempo_respuesta != null ? `${Number(device.tiempo_respuesta).toFixed(1)} ms` : "Sin respuesta al ping"],
  ];
  $("#drawer-fields").innerHTML = fields.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value || "No disponible")}</dd></div>`).join("");
  const services = serviceList(device.puertos);
  $("#drawer-services").innerHTML = services.length
    ? services.map((service) => `<span class="type-chip">${esc(service)}</span>`).join("")
    : '<p class="drawer-muted">No se detectaron servicios abiertos en el último escaneo con respuesta.</p>';
  const trusted = device.confianza === "confiable";
  $("#drawer-trust").innerHTML = `<div><strong>${trusted ? "Equipo revisado" : "Equipo pendiente de revisión"}</strong><span>${trusted ? "Forma parte del inventario confiable." : "Confírmalo si reconoces que pertenece a tu red."}</span></div><button class="button ${trusted ? "button-secondary" : "button-primary"}" id="drawer-trust-toggle" type="button">${trusted ? "Quitar confianza" : "Marcar como confiable"}</button>`;
  $("#drawer-trust-toggle").addEventListener("click", () => updateTrust(device, !trusted));
  $("#drawer-owner").value = device.responsable || "";
  $("#drawer-notes").value = device.notas || "";
  if (!$("#inventory-drawer").open) $("#inventory-drawer").showModal();
}

async function updateTrust(device, confiable) {
  const button = $("#drawer-trust-toggle");
  button.disabled = true;
  try {
    await api(withNetwork(`/api/dispositivos/${encodeURIComponent(device.ip)}/confianza`, device.red_id), { method: "PUT", body: JSON.stringify({ confiable }) });
    device.confianza = confiable ? "confiable" : "por_revisar";
    renderOverview();
    renderRows();
    openDrawer(deviceKey(device));
    showToast(confiable ? "Equipo añadido al inventario confiable." : "Equipo marcado para revisión.");
  } catch (error) {
    button.disabled = false;
    showToast(error.message);
  }
}

async function saveNotes() {
  const device = inventory.selected;
  if (!device) return;
  const button = $("#drawer-save");
  button.disabled = true;
  try {
    const result = await api(withNetwork(`/api/dispositivos/${encodeURIComponent(device.ip)}/notas`, device.red_id), {
      method: "PUT", body: JSON.stringify({ responsable: $("#drawer-owner").value, notas: $("#drawer-notes").value }),
    });
    device.responsable = result.responsable;
    device.notas = result.notas;
    renderRows();
    showToast("Responsable y notas guardados.");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
}

function exportCsv() {
  const rows = filteredDevices();
  if (!rows.length) return showToast("No hay equipos para exportar con esos filtros.");
  const columns = [
    ["Nombre", displayName], ["Red", networkLabel], ["IP", (d) => (d.ips || [d.ip]).join(" ")], ["MAC", (d) => d.mac], ["Tipo", (d) => typeLabel(d.tipo)],
    ["Sistema estimado", (d) => d.sistema], ["Fabricante", (d) => d.fabricante || d.fabricante_red], ["Modelo", (d) => d.modelo],
    ["Estado", (d) => d.estado], ["Confianza", (d) => d.confianza === "confiable" ? "Confiable" : "Por revisar"],
    ["Responsable", (d) => d.responsable], ["Notas", (d) => d.notas], ["Servicios", (d) => serviceList(d.puertos).join("; ")],
    ["Primera detección", (d) => d.primera_deteccion], ["Última detección", (d) => d.ultima_deteccion],
  ];
  const cell = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const csv = [columns.map(([title]) => cell(title)).join(","), ...rows.map((device) => columns.map(([, read]) => cell(read(device))).join(","))].join("\r\n");
  const url = URL.createObjectURL(new Blob(["﻿", csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `geareye-inventario-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(url);
  showToast(`Inventario exportado: ${rows.length} equipos.`);
}

async function loadInventory() {
  const button = $("#inventory-reload");
  button.disabled = true;
  try {
    const networkId = $("#inv-network").value;
    const payload = await api(withNetwork("/api/inventario", networkId));
    inventory.devices = Array.isArray(payload.dispositivos) ? payload.dispositivos : [];
    const red = inventory.networks.find((item) => String(item.id) === networkId);
    $("#inventory-subtitle").textContent = red
      ? `Equipos que GearEye ha detectado en ${red.nombre}, con la última información conocida de cada uno.`
      : "Todos los equipos que GearEye ha detectado en tus redes guardadas, con la última información conocida de cada uno.";
    $("#inventory-updated").textContent = `Actualizado ${new Date().toLocaleTimeString("es-CO", { hour: "2-digit", minute: "2-digit" })}`;
    renderOverview();
    renderRows();
  } catch (error) {
    $("#inventory-rows").innerHTML = `<tr><td colspan="8"><div class="empty-state"><strong>No se pudo cargar el inventario</strong><span>${esc(error.message)}</span></div></td></tr>`;
  } finally {
    button.disabled = false;
  }
}

async function start() {
  try {
    const session = await api("/auth/status");
    if (!session.authenticated) {
      window.location.href = "/app/";
      return;
    }
    inventory.role = session.role;
    document.body.classList.toggle("role-viewer", session.role === "viewer");
    const isAdmin = ["platform_admin", "company_admin"].includes(session.role);
    $("#admin-nav").hidden = !isAdmin;
    $("#admin-workspace-label").hidden = !isAdmin;
    const name = session.name || session.username || "GearEye";
    $("#profile-name").textContent = name;
    $("#profile-avatar").textContent = String(session.username || name).slice(0, 2).toUpperCase();
    $("#profile-company").textContent = session.company || "Sesión protegida";
  } catch (error) {
    $("#inventory-rows").innerHTML = `<tr><td colspan="8"><div class="empty-state"><strong>No se puede conectar con GearEye</strong><span>${esc(error.message)}</span></div></td></tr>`;
    return;
  }
  await loadNetworks();
  await loadInventory();
}

// Por defecto se muestra la misma red que el panel; "Todas las redes" reúne el inventario completo.
async function loadNetworks() {
  try {
    const payload = await api("/api/redes");
    inventory.networks = Array.isArray(payload.redes) ? payload.redes : [];
    const select = $("#inv-network");
    select.innerHTML = '<option value="">Todas las redes</option>' + inventory.networks
      .map((red) => `<option value="${red.id}">${esc(red.nombre)} · ${esc(red.subred)}</option>`).join("");
    const preferred = viewedNetwork() || String(payload.reciente || "");
    select.value = inventory.networks.some((red) => String(red.id) === preferred) ? preferred : "";
    $("#inv-network-wrap").hidden = inventory.networks.length < 2;
  } catch {
    $("#inv-network-wrap").hidden = true;
  }
}

// Las solicitudes autenticadas renuevan la sesión; se avisa actividad como mucho cada 15 s.
let lastActivity = 0;
["pointerdown", "keydown"].forEach((name) => document.addEventListener(name, () => {
  if (Date.now() - lastActivity < 15_000) return;
  lastActivity = Date.now();
  fetch(`${API_BASE}/auth/activity`, { method: "POST", credentials: "same-origin" })
    .then((response) => { if (response.status === 401) window.location.href = "/app/"; })
    .catch(() => {});
}, { passive: true }));

["#inv-search", "#inv-state", "#inv-trust", "#inv-seen", "#inv-sort"].forEach((selector) => $(selector).addEventListener(selector === "#inv-search" ? "input" : "change", renderRows));
$("#inv-network").addEventListener("change", loadInventory);
$("#inventory-reload").addEventListener("click", loadInventory);
$("#inventory-export").addEventListener("click", exportCsv);
$("#drawer-save").addEventListener("click", saveNotes);
$("#drawer-close").addEventListener("click", () => $("#inventory-drawer").close());
$("#inventory-drawer").addEventListener("click", (event) => { if (event.target.id === "inventory-drawer") event.target.close(); });
start();

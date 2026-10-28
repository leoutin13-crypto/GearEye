// Utilidades compartidas por el panel principal y la página de inventario.
const ICON_PATHS = {
  router: '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M8 9.5a6 6 0 0 1 8 0M5.5 7a9.5 9.5 0 0 1 13 0"/>',
  dispositivo_red: '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 11h2m3 0h2m3 0h1M7 14h10"/>',
  computador: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8m-4-4v4"/>',
  servidor: '<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/>',
  impresora: '<path d="M7 9V3h10v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v7H7z"/>',
  movil: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18h2"/>',
  camara: '<rect x="3" y="7" width="13" height="10" rx="2"/><path d="m16 11 5-3v8l-5-3"/>',
  tv: '<rect x="2.5" y="4" width="19" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
  iot: '<circle cx="12" cy="12" r="3"/><path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1m0-12.8-2.1 2.1m-8.6 8.6-2.1 2.1"/>',
  desconocido: '<circle cx="12" cy="12" r="8.5"/><path d="M12 8v4.5M12 16h.01"/>',
  alerta: '<path d="M12 3.5 2.5 20h19z"/><path d="M12 10v4.5M12 17.5h.01"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8h.01"/>',
  escudo: '<path d="M12 3 5 6v5c0 4.6 3 8.3 7 10 4-1.7 7-5.4 7-10V6z"/><path d="M12 9v4M12 16h.01"/>',
  nuevo: '<circle cx="12" cy="12" r="8.5"/><path d="M12 8v8M8 12h8"/>',
  cambio: '<path d="M4 9h13l-3-3M20 15H7l3 3"/>',
  ok: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  lapiz: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>',
};
const TYPE_LABELS = {
  router: "Router", dispositivo_red: "Equipo de red", computador: "Computador", servidor: "Servidor",
  impresora: "Impresora", movil: "Móvil", camara: "Cámara", tv: "Televisor", iot: "Dispositivo IoT",
  desconocido: "Sin clasificar",
};
const SERVICE_NAMES = {
  22: "SSH", 53: "DNS", 80: "HTTP", 135: "RPC de Windows", 139: "NetBIOS", 443: "HTTPS", 445: "Archivos compartidos",
  515: "Impresión LPD", 548: "Archivos de Apple", 554: "Video RTSP", 631: "Impresión IPP", 1883: "MQTT", 3389: "Escritorio remoto",
  5000: "Panel web NAS", 5357: "Descubrimiento de Windows", 6668: "Tuya", 8001: "Control de Smart TV", 8008: "Google Cast",
  8009: "Google Cast", 8080: "HTTP alternativo", 8554: "Video RTSP", 9100: "Impresión directa", 37777: "Video Dahua",
  62078: "Sincronización iPhone/iPad",
};

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}

function icon(name) {
  return `<svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[name] || ICON_PATHS.desconocido}</svg>`;
}

function deviceIcon(device) {
  return icon(ICON_PATHS[device.tipo] ? device.tipo : "desconocido");
}

function typeLabel(type) {
  return TYPE_LABELS[type] || (type ? type.charAt(0).toUpperCase() + type.slice(1).replaceAll("_", " ") : "Sin clasificar");
}

function capitalize(value) {
  return value ? String(value).charAt(0).toUpperCase() + String(value).slice(1) : value;
}

// Sin nombre de host, el equipo se nombra por su tipo, su fabricante y el final de la IP.
function displayName(device) {
  if (device.nombre) return device.nombre;
  const vendor = device.fabricante || (device.fabricante_red && !["Desconocido", "MAC privada"].includes(device.fabricante_red) ? device.fabricante_red : null);
  const suffix = String(device.ip || "").split(".").pop();
  return `${typeLabel(device.tipo)} ${vendor ? vendor.split(/[ ,]/)[0] : ""}${suffix ? ` .${suffix}` : ""}`.replace(/\s+/g, " ").trim();
}

function serviceList(ports) {
  return (ports || []).map((port) => SERVICE_NAMES[port] ? `${SERVICE_NAMES[port]} (${port})` : `Puerto ${port}`);
}

function relativeSeen(value) {
  if (!value) return "Sin fecha";
  const minutes = Math.round((Date.now() - new Date(value).getTime()) / 60000);
  if (minutes < 2) return "Ahora";
  if (minutes < 60) return `Hace ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `Hace ${hours} h`;
  const days = Math.round(hours / 24);
  return days === 1 ? "Ayer" : `Hace ${days} días`;
}

// Red que el usuario eligió ver. Vacío: la red a la que está conectado ahora.
const NETWORK_STORAGE_KEY = "geareye.red";

function viewedNetwork() {
  try { return localStorage.getItem(NETWORK_STORAGE_KEY) || ""; } catch { return ""; }
}

function setViewedNetwork(id) {
  try {
    if (id) localStorage.setItem(NETWORK_STORAGE_KEY, String(id));
    else localStorage.removeItem(NETWORK_STORAGE_KEY);
  } catch { /* Sin almacenamiento se sigue la red conectada. */ }
}

function withNetwork(path, id) {
  return id ? `${path}${path.includes("?") ? "&" : "?"}red=${encodeURIComponent(id)}` : path;
}

function gatewaySummary(red) {
  if (!red) return "";
  return [red.gateway ? `Gateway ${red.gateway}` : "Gateway sin identificar", red.gateway_fabricante, red.gateway_mac].filter(Boolean).join(" · ");
}

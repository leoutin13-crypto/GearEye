const API_BASE = window.location.protocol === "file:" ? "http://127.0.0.1:8000" : window.location.origin;
const $ = (selector) => document.querySelector(selector);
const admin = { companies: [], people: [], role: null, company: "", confirm: null, busy: null };
const ROLE_NAMES = { platform_admin: "Administrador general", company_admin: "Administrador de empresa", viewer: "Solo consulta" };
const STATUS_ORDER = { invited: 0, expired: 1, active: 2, disabled: 3 };

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(showToast.timeout);
  showToast.timeout = setTimeout(() => toast.classList.remove("show"), 4200);
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
  if (!response.ok) throw new Error(typeof payload.detail === "string" ? payload.detail : `La API respondió ${response.status}`);
  return payload;
}

const isPlatformAdmin = () => admin.role === "platform_admin";
const keyOf = (person) => `${person.kind}:${person.id}`;
const isPending = (person) => person.status === "invited" || person.status === "expired";
const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`;

function initials(name) {
  const words = String(name || "?").trim().split(/\s+/);
  return (words.length > 1 ? words[0][0] + words[words.length - 1][0] : words[0].slice(0, 2)).toUpperCase();
}

function fromSeconds(seconds) {
  return seconds ? new Date(seconds * 1000) : null;
}

function invitationNote(person) {
  if (person.status === "expired") return `Venció ${relativeSeen(fromSeconds(person.expires_at)).toLocaleLowerCase("es")}`;
  const hours = Math.ceil((person.expires_at * 1000 - Date.now()) / 3_600_000);
  return hours <= 1 ? "Vence en menos de 1 h" : `Vence en ${hours} h`;
}

// ── Carga ─────────────────────────────────────────────────────────────

async function start() {
  try {
    const session = await api("/auth/status");
    if (!session.authenticated) { window.location.href = "/app/"; return; }
    const name = session.name || session.username || "GearEye";
    $("#profile-name").textContent = name;
    $("#profile-avatar").textContent = initials(name);
    $("#profile-company").textContent = session.role === "platform_admin" ? "Administración general" : (session.company || "Sesión protegida");
    if (!["platform_admin", "company_admin"].includes(session.role)) {
      $("#admin-denied").hidden = false;
      $("#admin-subtitle").textContent = "Tu cuenta no tiene permisos de administración.";
      return;
    }
    admin.role = session.role;
    admin.company = session.company || "";
    $("#admin-actions").hidden = false;
    $("#admin-content").hidden = false;
    $("#open-company").hidden = !isPlatformAdmin();
    $("#companies-section").hidden = !isPlatformAdmin();
    $("#company-filter-wrap").hidden = !isPlatformAdmin();
    $("#invite-company-field").hidden = !isPlatformAdmin();
    document.querySelectorAll(".col-company").forEach((node) => { node.hidden = !isPlatformAdmin(); });
    $("#admin-subtitle").textContent = isPlatformAdmin()
      ? "Personas con acceso a GearEye en todas las empresas, su rol y el estado de cada cuenta."
      : `Personas con acceso a la red de ${admin.company || "tu empresa"}, su rol y el estado de cada cuenta.`;
    await loadOverview();
  } catch (error) {
    $("#admin-content").hidden = false;
    $("#admin-users").innerHTML = emptyRow(5, "No se puede conectar con GearEye", error.message);
  }
}

async function loadOverview() {
  const button = $("#admin-refresh");
  button.disabled = true;
  try {
    const overview = await api("/auth/admin/overview");
    admin.companies = overview.companies || [];
    admin.people = overview.users || [];
    admin.confirm = null;
    renderCompanies();
    renderFacts();
    renderPeople();
  } catch (error) {
    $("#admin-users").innerHTML = emptyRow(5, "No se pudieron cargar las personas", error.message);
  } finally {
    button.disabled = false;
  }
}

// ── Resumen y empresas ────────────────────────────────────────────────

function renderFacts() {
  const people = admin.people;
  const pending = people.filter(isPending);
  const expired = pending.filter((person) => person.status === "expired").length;
  const facts = [
    isPlatformAdmin()
      ? ["Empresas", admin.companies.length, plural(admin.companies.filter((c) => c.status === "waiting_agent").length, "espera su agente", "esperan su agente")]
      : ["Empresa", admin.company || "—", "Tu ámbito de administración"],
    ["Personas activas", people.filter((p) => p.status === "active").length, "Pueden iniciar sesión"],
    ["Invitaciones pendientes", pending.length, expired ? plural(expired, "vencida: reenvíala", "vencidas: reenvíalas") : "Sin invitaciones vencidas"],
    ["Cuentas desactivadas", people.filter((p) => p.status === "disabled").length, "Sin acceso a GearEye"],
  ];
  $("#admin-facts").innerHTML = facts.map(([label, value, note]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd><span class="fact-note">${esc(note)}</span></div>`).join("");
  const badge = $("#nav-pending");
  badge.textContent = pending.length;
  badge.hidden = !pending.length;
}

function agentCell(company) {
  if (company.status === "waiting_agent") {
    return `<span class="access-state waiting">Esperando agente</span><span class="cell-sub">Aún no llega el primer escaneo de la sede</span>`;
  }
  if (!company.last_agent_report) {
    return `<span class="access-state">Escaneo local</span><span class="cell-sub">La red se escanea desde este servidor</span>`;
  }
  return `<span class="access-state">Conectado</span><span class="cell-sub">Último reporte: ${esc(relativeSeen(fromSeconds(company.last_agent_report)).toLocaleLowerCase("es"))}</span>`;
}

function renderCompanies() {
  const companies = [...admin.companies].sort((a, b) => a.name.localeCompare(b.name, "es"));
  $("#company-total").textContent = plural(companies.length, "empresa", "empresas");
  const created = (company) => fromSeconds(company.created_at)?.toLocaleDateString("es-CO", { day: "numeric", month: "short", year: "numeric" });
  $("#admin-companies").innerHTML = companies.map((company) => `<tr>
      <td><strong>${esc(company.name)}</strong>${created(company) ? `<span class="cell-sub">Creada el ${esc(created(company))}</span>` : ""}</td>
      <td data-label="Personas" class="num ${company.user_count ? "" : "zero"}">${company.user_count}</td>
      <td data-label="Invitaciones" class="num ${company.pending_invitations ? "" : "zero"}">${company.pending_invitations || 0}</td>
      <td data-label="Agente de red">${agentCell(company)}</td>
    </tr>`).join("") || emptyRow(4, "Aún no hay empresas", "Crea la primera con «Nueva empresa».");

  const options = companies.map((company) => `<option value="${esc(company.id)}">${esc(company.name)}</option>`).join("");
  const filter = $("#user-company-filter");
  const selected = filter.value;
  filter.innerHTML = `<option value="">Todas</option>${options}`;
  if (companies.some((company) => company.id === selected)) filter.value = selected;
  const invite = $("#invite-company");
  const chosen = invite.value;
  invite.innerHTML = options;
  if (companies.some((company) => company.id === chosen)) invite.value = chosen;
}

// ── Personas ──────────────────────────────────────────────────────────

function emptyRow(columns, title, detail) {
  return `<tr><td colspan="${columns}"><div class="empty-state"><strong>${esc(title)}</strong><span>${esc(detail)}</span></div></td></tr>`;
}

function canManage(person) {
  return person.kind === "user" && !person.is_self && person.role !== "platform_admin";
}

function roleCell(person) {
  if (canManage(person) && person.status === "active") {
    const options = ["company_admin", "viewer"].map((role) => `<option value="${role}" ${person.role === role ? "selected" : ""}>${ROLE_NAMES[role]}</option>`).join("");
    return `<select class="admin-role-select" data-role-for="${esc(person.id)}" aria-label="Rol de ${esc(person.name)}" ${admin.busy === keyOf(person) ? "disabled" : ""}>${options}</select>`;
  }
  return `<span class="role-pill role-${esc(person.role)}">${esc(ROLE_NAMES[person.role] || person.role_label || "Invitado")}</span>`;
}

function stateCell(person) {
  const labels = { active: "Activa", disabled: "Desactivada", invited: "Invitación enviada", expired: "Invitación vencida" };
  const note = isPending(person) ? `<span class="cell-sub">${esc(invitationNote(person))}</span>` : "";
  return `<span class="access-state ${esc(person.status)}">${labels[person.status] || "Activa"}</span>${note}`;
}

const CONFIRM_COPY = {
  disable: (person) => [`¿Desactivar a ${person.name.split(" ")[0]}? Perderá el acceso de inmediato.`, "Desactivar"],
  revoke: () => ["¿Anular la invitación? El enlace dejará de funcionar.", "Anular"],
};

function actionsCell(person) {
  const key = keyOf(person);
  const busy = admin.busy === key ? "disabled" : "";
  if (admin.confirm?.key === key) {
    const [question, verb] = CONFIRM_COPY[admin.confirm.action](person);
    return `<div class="row-confirm" role="group" aria-label="Confirmar acción"><span>${esc(question)}</span><button class="button button-secondary" type="button" data-action="cancel" ${busy}>Cancelar</button><button class="button button-danger solid" type="button" data-action="${admin.confirm.action}" data-confirmed="true" ${busy}>${verb}</button></div>`;
  }
  if (person.is_self) return `<div class="row-actions"><span class="row-note">Tu cuenta</span></div>`;
  if (person.kind === "invitation") {
    return `<div class="row-actions"><button class="button button-secondary" type="button" data-action="resend" ${busy}>${person.status === "expired" ? "Reenviar invitación" : "Reenviar"}</button><button class="button button-danger" type="button" data-action="revoke" ${busy}>Anular</button></div>`;
  }
  if (!canManage(person)) return `<div class="row-actions"><span class="row-note">Cuenta protegida</span></div>`;
  return person.status === "disabled"
    ? `<div class="row-actions"><button class="button button-secondary" type="button" data-action="enable" ${busy}>Reactivar</button></div>`
    : `<div class="row-actions"><button class="button button-danger" type="button" data-action="disable" ${busy}>Desactivar</button></div>`;
}

function filteredPeople() {
  const search = $("#user-search").value.trim().toLocaleLowerCase("es");
  const company = $("#user-company-filter").value;
  const role = $("#user-role-filter").value;
  const status = $("#user-status-filter").value;
  return admin.people
    .filter((person) => !search || `${person.name} ${person.email}`.toLocaleLowerCase("es").includes(search))
    .filter((person) => !company || person.company_id === company)
    .filter((person) => !role || person.role === role)
    .filter((person) => !status || (status === "pending" ? isPending(person) : person.status === status))
    .sort((a, b) => (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9) || a.name.localeCompare(b.name, "es"));
}

function renderPeople() {
  const people = filteredPeople();
  const total = admin.people.length;
  $("#user-total").textContent = people.length === total ? plural(total, "persona", "personas") : `${people.length} de ${total}`;
  if (!people.length) {
    $("#admin-users").innerHTML = total
      ? emptyRow(5, "Nadie coincide con esos filtros", "Cambia la búsqueda o los filtros.")
      : emptyRow(5, "Aún no hay personas", "Invita a la primera con «Invitar persona».");
    return;
  }
  $("#admin-users").innerHTML = people.map((person) => {
    const avatarState = isPending(person) ? "invited" : person.status === "disabled" ? "disabled" : "";
    return `<tr data-key="${esc(keyOf(person))}" class="${person.status === "disabled" ? "row-disabled" : ""}">
      <td><div class="person-cell"><span class="person-avatar ${avatarState}" aria-hidden="true">${esc(initials(person.name))}</span><span class="person-copy"><strong>${esc(person.name)}${person.is_self ? '<span class="you-tag">Tú</span>' : ""}</strong><span>${esc(person.email)}</span></span></div></td>
      <td class="col-company" ${isPlatformAdmin() ? "" : "hidden"}>${esc(person.company_name || "—")}</td>
      <td class="cell-role">${roleCell(person)}</td>
      <td class="cell-state">${stateCell(person)}</td>
      <td class="cell-actions">${actionsCell(person)}</td>
    </tr>`;
  }).join("");
}

function replacePerson(updated) {
  admin.people = admin.people.map((person) => (person.kind === updated.kind && person.id === updated.id ? updated : person));
}

async function runAction(person, action) {
  const key = keyOf(person);
  admin.busy = key;
  renderPeople();
  try {
    if (action === "disable" || action === "enable") {
      replacePerson(await api(`/auth/admin/users/${encodeURIComponent(person.id)}`, { method: "PATCH", body: JSON.stringify({ disabled: action === "disable" }) }));
      showToast(action === "disable" ? `${person.name} ya no puede entrar a GearEye.` : `${person.name} puede volver a entrar a GearEye.`);
    } else if (action === "revoke") {
      await api(`/auth/admin/invitations/${encodeURIComponent(person.id)}`, { method: "DELETE" });
      admin.people = admin.people.filter((item) => keyOf(item) !== key);
      showToast(`Invitación a ${person.email} anulada.`);
    } else if (action === "resend") {
      await api(`/auth/admin/invitations/${encodeURIComponent(person.id)}/resend`, { method: "POST" });
      showToast(`Invitación reenviada a ${person.email}. El enlace anterior ya no funciona.`);
      admin.busy = null;
      await loadOverview();
      return;
    }
  } catch (error) {
    showToast(error.message);
  } finally {
    admin.busy = null;
    admin.confirm = null;
  }
  renderFacts();
  renderCompanies();
  renderPeople();
}

$("#admin-users").addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const person = admin.people.find((item) => keyOf(item) === button.closest("tr").dataset.key);
  const action = button.dataset.action;
  if (action === "cancel") { admin.confirm = null; renderPeople(); return; }
  if (CONFIRM_COPY[action] && !button.dataset.confirmed) {
    admin.confirm = { key: keyOf(person), action };
    renderPeople();
    document.querySelector(`tr[data-key="${CSS.escape(keyOf(person))}"] [data-confirmed]`)?.focus();
    return;
  }
  runAction(person, action);
});

$("#admin-users").addEventListener("change", async (event) => {
  const select = event.target.closest("[data-role-for]");
  if (!select) return;
  const person = admin.people.find((item) => item.kind === "user" && item.id === select.dataset.roleFor);
  admin.busy = keyOf(person);
  select.disabled = true;
  try {
    replacePerson(await api(`/auth/admin/users/${encodeURIComponent(person.id)}`, { method: "PATCH", body: JSON.stringify({ role: select.value }) }));
    showToast(`${person.name} ahora es ${ROLE_NAMES[select.value].toLocaleLowerCase("es")}.`);
  } catch (error) {
    showToast(error.message);
  } finally {
    admin.busy = null;
    renderPeople();
  }
});

// ── Formularios desplegables ──────────────────────────────────────────

const COMPOSERS = { "invite-form": "#open-invite", "company-form": "#open-company" };

function setComposer(id) {
  Object.entries(COMPOSERS).forEach(([formId, buttonSelector]) => {
    const open = formId === id;
    $(`#${formId}`).hidden = !open;
    $(buttonSelector).setAttribute("aria-expanded", String(open));
  });
  if (id) {
    if (id === "invite-form" && $("#user-company-filter").value) $("#invite-company").value = $("#user-company-filter").value;
    $(`#${id} input`).focus();
  }
}

$("#open-invite").addEventListener("click", () => setComposer($("#invite-form").hidden ? "invite-form" : null));
$("#open-company").addEventListener("click", () => setComposer($("#company-form").hidden ? "company-form" : null));
document.querySelectorAll("[data-close-composer]").forEach((button) => button.addEventListener("click", () => {
  const opener = COMPOSERS[button.closest("form").id];
  setComposer(null);
  $(opener).focus();
}));
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (admin.confirm) { admin.confirm = null; renderPeople(); return; }
  const open = Object.keys(COMPOSERS).find((id) => !$(`#${id}`).hidden);
  if (open) { setComposer(null); $(COMPOSERS[open]).focus(); }
});

async function submitComposer(event, path, done) {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('[type="submit"]');
  submit.disabled = true;
  try {
    const payload = Object.fromEntries(new FormData(form).entries());
    const result = await api(`/auth/admin/${path}`, { method: "POST", body: JSON.stringify(payload) });
    form.reset();
    setComposer(null);
    showToast(done(result));
    await loadOverview();
  } catch (error) {
    showToast(error.message);
  } finally {
    submit.disabled = false;
  }
}

$("#invite-form").addEventListener("submit", (event) => submitComposer(event, "invitations", (result) => `Invitación enviada a ${result.email}.`));
$("#company-form").addEventListener("submit", (event) => submitComposer(event, "companies", (result) => `${result.name} creada. Enviamos la bienvenida a ${result.email}.`));

["#user-company-filter", "#user-role-filter", "#user-status-filter"].forEach((selector) => $(selector).addEventListener("change", renderPeople));
$("#user-search").addEventListener("input", renderPeople);
$("#admin-refresh").addEventListener("click", loadOverview);
$("#admin-logout").addEventListener("click", async () => {
  try { await api("/auth/logout", { method: "POST" }); } catch { /* Se sale igual. */ }
  window.location.replace("/app/");
});

// Las solicitudes autenticadas renuevan la sesión; se avisa actividad como mucho cada 15 s.
let lastActivity = 0;
["pointerdown", "keydown"].forEach((name) => document.addEventListener(name, () => {
  if (Date.now() - lastActivity < 15_000) return;
  lastActivity = Date.now();
  fetch(`${API_BASE}/auth/activity`, { method: "POST", credentials: "same-origin" })
    .then((response) => { if (response.status === 401) window.location.href = "/app/"; })
    .catch(() => {});
}, { passive: true }));

start();

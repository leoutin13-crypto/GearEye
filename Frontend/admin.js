const api = window.location.protocol === "file:" ? "http://127.0.0.1:8000" : window.location.origin;
const $ = (selector) => document.querySelector(selector);
const data = { companies: [], users: [], role: null };
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("visible");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("visible"), 3800);
}

async function request(path, options = {}) {
  const response = await fetch(`${api}${path}`, { credentials: "same-origin", ...options, headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers } });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `La API respondió ${response.status}.`);
  return payload;
}

async function loadAdmin() {
  try {
    const session = await request("/auth/status");
    if (!session.authenticated) { window.location.replace("/app/"); return; }
    if (!["platform_admin", "company_admin"].includes(session.role)) {
      $("#admin-denied").hidden = false;
      $("#admin-content").hidden = true;
      return;
    }
    data.role = session.role;
    $("#admin-name").textContent = session.name || session.username;
    $("#admin-company").textContent = session.role === "platform_admin" ? "Administración general" : (session.company || "");
    $("#return-network").hidden = false;
    $("#admin-content").hidden = false;
    $("#admin-denied").hidden = true;
    $("#company-form").hidden = session.role !== "platform_admin";
    $("#companies-section").hidden = session.role !== "platform_admin";
    const overview = await request("/auth/admin/overview");
    data.companies = overview.companies || [];
    data.users = overview.users || [];
    renderCompanies();
    renderUsers();
  } catch (error) {
    toast(error.message);
  }
}

function renderCompanies() {
  const companies = data.companies;
  $("#company-total").textContent = `${companies.length} ${companies.length === 1 ? "empresa" : "empresas"}`;
  $("#admin-companies").innerHTML = companies.map((company) => `<tr><td><strong>${esc(company.name)}</strong></td><td>${esc(company.user_count)}</td><td><span class="admin-status ${company.status === "waiting_agent" ? "pending" : "active"}"><i></i>${company.status === "waiting_agent" ? "Agente pendiente" : "Agente conectado"}</span></td></tr>`).join("") || `<tr><td colspan="3">Aún no hay empresas.</td></tr>`;
  const options = companies.map((company) => `<option value="${esc(company.id)}">${esc(company.name)}</option>`).join("");
  $("#invite-company").innerHTML = options;
  const selected = $("#user-company-filter").value;
  $("#user-company-filter").innerHTML = `<option value="">Todas las empresas</option>${options}`;
  if (companies.some((company) => company.id === selected)) $("#user-company-filter").value = selected;
}

function renderUsers() {
  const search = $("#user-search").value.trim().toLocaleLowerCase("es");
  const companyId = $("#user-company-filter").value;
  const role = $("#user-role-filter").value;
  const names = { platform_admin: "Administrador general", company_admin: "Administrador de empresa", viewer: "Solo consulta" };
  const users = data.users.filter((user) => (!search || `${user.name} ${user.email}`.toLocaleLowerCase("es").includes(search)) && (!companyId || user.company_id === companyId) && (!role || user.role === role));
  $("#user-total").textContent = `${users.length} ${users.length === 1 ? "usuario" : "usuarios"}`;
  $("#admin-users").innerHTML = users.map((user) => `<tr><td><strong>${esc(user.name)}</strong></td><td>${esc(user.email)}</td><td>${esc(user.company_name)}</td><td><span class="role-pill role-${esc(user.role)}">${esc(names[user.role] || "Invitado")}</span></td><td><span class="admin-status ${user.disabled ? "disabled" : "active"}"><i></i>${user.disabled ? "Desactivado" : "Activo"}</span></td></tr>`).join("") || `<tr><td colspan="5">No hay usuarios que coincidan con esos filtros.</td></tr>`;
}

async function post(path, form) {
  return request(`/auth/admin/${path}`, { method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(form).entries())) });
}

$("#admin-refresh").addEventListener("click", loadAdmin);
$("#user-search").addEventListener("input", renderUsers);
$("#user-company-filter").addEventListener("change", renderUsers);
$("#user-role-filter").addEventListener("change", renderUsers);
$("#company-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const result = await post("companies", form);
    form.reset();
    await loadAdmin();
    toast(`Empresa creada. Enviamos el correo de bienvenida a ${result.email}.`);
  } catch (error) { toast(error.message); }
});
$("#invite-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    await post("invitations", form);
    form.reset();
    toast("Invitación enviada por correo.");
    await loadAdmin();
  } catch (error) { toast(error.message); }
});
$("#admin-logout").addEventListener("click", async () => {
  try { await request("/auth/logout", { method: "POST" }); } finally { window.location.replace("/app/"); }
});
loadAdmin();

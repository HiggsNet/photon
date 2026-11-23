const get = (id) => document.getElementById(id);
const links = { h24: "公网 IPv4 · H2", h26: "公网 IPv6 · H2", h2p: "Photon Mesh · H2" };
let token = "";
let endpoints = [];
let editing = "";

function status(message) { get("status").textContent = message; }
async function api(path, method = "GET", body) {
  const headers = new Headers();
  if (token) headers.set("Authorization", "Bearer " + token);
  if (body !== undefined) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!response.ok) {
    const data = await response.text();
    try {
      const detail = JSON.parse(data);
      throw new Error(detail.error || detail.message || data.trim());
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
      throw new Error(response.status === 401 ? "请输入正确的管理令牌。" : data.trim());
    }
  }
  if (response.status !== 204) return response.json();
}

function button(label, onClick) {
  const element = document.createElement("button");
  element.type = "button";
  element.textContent = label;
  element.addEventListener("click", onClick);
  return element;
}
function splitHop(hop) {
  const [selector, link] = hop.split("@");
  const [zone, id] = selector.split("/");
  const aliases = { "public-v4": "h24", "public-v6": "h26", photon: "h2p" };
  return { zone, id: id || "", link: aliases[link] || link || "h2p" };
}
function hopRow(hop = "") {
  const value = splitHop(hop);
  const row = document.createElement("div");
  row.className = "hop";
  const zoneInput = Object.assign(document.createElement("input"), { value: value.zone, required: true, placeholder: "Zone" });
  const exitInput = Object.assign(document.createElement("input"), { value: value.id, placeholder: "默认" });
  const linkInput = document.createElement("select");
  Object.entries(links).forEach(([key, label]) => linkInput.append(new Option(label, key, false, key === value.link)));
  const idList = "zones";
  zoneInput.setAttribute("list", idList);
  const constrain = () => {
    const node = endpoints.find((item) => item.zone === zoneInput.value && item.endpoint === (exitInput.value || "exit"))
      || endpoints.find((item) => item.zone === zoneInput.value);
    for (const option of linkInput.options) {
      option.disabled = Boolean(node && !node.links.includes(option.value));
    }
    if (linkInput.selectedOptions[0]?.disabled && node) linkInput.value = node.links[0];
  };
  zoneInput.addEventListener("change", constrain);
  exitInput.addEventListener("change", constrain);
  function field(label, input) {
    const element = document.createElement("label");
    element.append(label, input);
    return element;
  }
  row.append(field("Zone", zoneInput), field("出口名", exitInput), field("连接方式", linkInput),
    button("移除", () => { row.remove(); if (!get("hops").children.length) hopRow(); }));
  row.read = () => [zoneInput.value.trim(), exitInput.value.trim(), linkInput.value];
  get("hops").append(row);
  constrain();
}
function formHops() {
  return [...get("hops").children].map((row, index, all) => {
    const [zone, exit, link] = row.read();
    if (!zone) throw new Error("请填写每一跳的 Zone。");
    if (exit && index !== all.length - 1) throw new Error("只有最后一跳可以指定出口名。");
    return zone + (exit ? "/" + exit : "") + "@" + link;
  });
}
function edit(route) {
  editing = route?.name || "";
  get("edit-title").textContent = editing ? "切换路径" : "新建路径";
  get("save").textContent = editing ? "保存切换" : "创建路径";
  get("name").value = editing;
  get("name").readOnly = Boolean(editing);
  get("listen").value = route?.listen || "";
  get("listen").readOnly = Boolean(editing);
  get("udp-prefixes").value = (route?.udp_prefixes || []).join(", ");
  get("hops").replaceChildren();
  (route?.hops || [""]).forEach(hopRow);
}
function renderRoutes(routes) {
  const body = get("routes");
  body.replaceChildren();
  if (!routes.length) {
    const cell = body.insertRow().insertCell();
    cell.colSpan = 4; cell.className = "empty"; cell.textContent = "暂无路径";
  }
  for (const route of routes) {
    const row = body.insertRow();
    row.insertCell().textContent = route.name;
    row.insertCell().textContent = route.listen;
    row.insertCell().textContent = route.hops.join(" → ");
    const actions = row.insertCell();
    actions.append(button("切换", () => { edit(route); get("name").focus(); }), " ",
      button("测试", () => attempt(() => probe(route.name))));
  }
}
function renderCandidates(data) {
  endpoints = data.endpoints;
  let zones = get("zones");
  if (!zones) { zones = document.createElement("datalist"); zones.id = "zones"; document.body.append(zones); }
  zones.replaceChildren(...[...new Set(endpoints.map((node) => node.zone))].map((zone) => new Option(zone)));
  const list = get("candidates");
  list.replaceChildren();
  for (const path of data.paths) {
    const item = document.createElement("li");
    item.append(button(path.join(" → "), () => {
      get("hops").replaceChildren();
      path.forEach(hopRow);
      get("name").focus();
    }));
    list.append(item);
  }
}
async function discover() {
  const target = get("target").value.trim();
  const query = new URLSearchParams({ protocol: get("protocol").value });
  if (target) query.set("target", target);
  const data = await api("/v1/candidates?" + query);
  renderCandidates(data);
  get("result").textContent = "找到 " + data.paths.length + " 条候选路径。";
}
async function refresh() {
  const [routes, data] = await Promise.all([api("/v1/routes"), api("/v1/candidates")]);
  renderRoutes(routes);
  renderCandidates(data);
  status("");
}
async function probe(name = "") {
  const target = get("target").value.trim();
  if (!target) throw new Error("请填写测试目标。");
  const request = { protocol: get("protocol").value, target };
  if (!name) request.hops = formHops();
  get("result").textContent = "正在测路…";
  const path = name ? "/v1/routes/" + encodeURIComponent(name) + "/probe" : "/v1/probe";
  const result = await api(path, "POST", request);
  get("result").textContent = result.ok ? "连接成功 · " + result.elapsed_ms + " ms"
    : "连接失败" + (result.failed_hop === undefined ? "" : " · 第 " + (result.failed_hop + 1) + " 跳") + " · " + result.error;
}
async function attempt(action) {
  try { await action(); } catch (error) { status(error.message); }
}
get("auth").addEventListener("submit", (event) => {
  event.preventDefault();
  token = get("token").value.trim();
  attempt(refresh);
});
get("refresh").onclick = () => attempt(refresh);
get("add-hop").onclick = () => hopRow();
get("reset").onclick = () => edit();
get("discover").addEventListener("submit", (event) => { event.preventDefault(); attempt(discover); });
get("probe").onclick = () => attempt(() => probe());
get("route-form").addEventListener("submit", (event) => {
  event.preventDefault();
  attempt(async () => {
    const body = { hops: formHops(), udp_prefixes: get("udp-prefixes").value.split(",").map((value) => value.trim()).filter(Boolean) };
    if (editing) await api("/v1/routes/" + encodeURIComponent(editing), "PUT", body);
    else {
      body.name = get("name").value.trim();
      body.listen = get("listen").value.trim();
      await api("/v1/routes", "POST", body);
    }
    edit();
    await refresh();
    status("已保存路径。");
  });
});
edit();
attempt(refresh);

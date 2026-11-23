const get = (id) => document.getElementById(id);
const links = { h24: "公网 IPv4", h26: "公网 IPv6", h2p: "Photon Mesh" };
const aliases = { "public-v4": "h24", "public-v6": "h26", photon: "h2p" };
const relayLimit = 7;
let token = "";
let directory = { origin: "", ready: false, exits: [], relays: [] };
let settings = null;
let editing = null;
let testing = null;
let pendingProbe = null;
let exitRow;
let relayRows = [];

function status(message) { get("status").textContent = message; }
async function api(path, method = "GET", body, signal) {
  const headers = new Headers();
  if (token) headers.set("Authorization", "Bearer " + token);
  if (body !== undefined) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { method, headers, signal, body: body === undefined ? undefined : JSON.stringify(body) });
  if (response.status === 401) throw new Error("请输入正确的管理令牌。");
  if (!response.ok) {
    const data = await response.text();
    let detail;
    try { detail = JSON.parse(data); } catch {}
    throw new Error(detail?.error || detail?.message || data.trim() || "请求失败");
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
function textElement(tag, text, className = "") {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}
function field(label, input) {
  const element = document.createElement("label");
  element.append(label, input);
  return element;
}
function parentZone() { return directory.origin.split(".").slice(1).join("."); }
function fullZone(zone) {
  return !zone || zone.endsWith(".") ? zone : zone + "." + parentZone();
}
function shortZone(zone) {
  const parent = parentZone();
  return parent && zone.endsWith("." + parent) ? zone.slice(0, -parent.length - 1) : zone;
}
function selector(node) {
  return node.zone + (node.role === "exit" && node.endpoint !== "exit" ? "/" + node.endpoint : "");
}
function nodeName(value) {
  const [zone, id] = value.split("/");
  return shortZone(zone) + (id && id !== "exit" ? " / " + id : "");
}
function splitHop(hop) {
  const [name, link = ""] = hop.split("@");
  const [zone, id] = name.split("/");
  return { node: fullZone(zone) + (id && id !== "exit" ? "/" + id : ""), link: aliases[link] || link };
}

function hopRow(role, hop = "") {
  const initial = splitHop(hop);
  const row = document.createElement("div");
  row.className = "hop";
  const node = document.createElement("select");
  const link = document.createElement("select");
  node.required = true;
  link.required = true;
  function renderLinks(selected) {
    const known = directory[role === "exit" ? "exits" : "relays"].find((candidate) => selector(candidate) === node.value);
    link.replaceChildren(new Option("选择连接方式", ""));
    for (const code of known?.links || []) link.append(new Option(links[code] || code, code));
    if (selected && !known?.links.includes(selected)) {
      link.append(new Option((links[selected] || selected) + "（目录未提供）", selected, false, true));
    }
    link.value = selected || "";
    link.disabled = !node.value;
  }
  function renderNodes(selected, selectedLink) {
    node.replaceChildren(new Option(role === "exit" ? "选择出口" : "选择中继", ""));
    for (const candidate of directory[role === "exit" ? "exits" : "relays"]) {
      const value = selector(candidate);
      node.append(new Option(nodeName(value), value));
    }
    if (selected && ![...node.options].some((option) => option.value === selected)) {
      node.append(new Option(nodeName(selected) + "（目录未提供）", selected));
    }
    node.value = selected || "";
    renderLinks(selectedLink);
  }
  const item = {
    row, node, link,
    refresh() { renderNodes(node.value, link.value); },
    choose(value) {
      const previousLink = node.value === value ? link.value : "";
      renderNodes(value, previousLink);
      link.focus();
    },
  };
  node.addEventListener("change", () => { renderLinks(""); preview(); });
  link.addEventListener("change", preview);
  row.append(field(role === "exit" ? "出口节点" : "中继节点", node), field("连接方式", link));
  if (role === "relay") {
    const actions = document.createElement("div");
    actions.className = "hop-actions";
    const move = (offset) => {
      const index = relayRows.indexOf(item);
      const next = index + offset;
      if (next < 0 || next >= relayRows.length) return;
      [relayRows[index], relayRows[next]] = [relayRows[next], relayRows[index]];
      renderRelays();
      item.node.focus();
    };
    item.up = button("上移", () => move(-1));
    item.down = button("下移", () => move(1));
    actions.append(item.up, item.down, button("移除", () => {
      relayRows = relayRows.filter((candidate) => candidate !== item);
      renderRelays();
      get("add-relay").focus();
    }));
    row.append(actions);
  }
  renderNodes(initial.node, initial.link);
  return item;
}
function renderRelays() {
  for (const [index, row] of relayRows.entries()) {
    row.up.hidden = relayRows.length < 2;
    row.down.hidden = relayRows.length < 2;
    row.up.disabled = index === 0;
    row.down.disabled = index === relayRows.length - 1;
  }
  get("relays").replaceChildren(...relayRows.map((item) => item.row));
  get("add-relay").disabled = relayRows.length >= relayLimit;
  preview();
}
function addRelay(value = "") {
  if (relayRows.length >= relayLimit) throw new Error("一条路径最多经过七个中继。");
  const existing = value && relayRows.find((item) => item.node.value === value);
  if (existing) { existing.link.focus(); return; }
  const item = hopRow("relay");
  relayRows.push(item);
  renderRelays();
  if (value) { item.choose(value); preview(); }
  else item.node.focus();
}
function describeHop(hop, index, length) {
  const value = splitHop(hop);
  const role = index === length - 1 ? "出口" : "中继";
  return role + " " + nodeName(value.node) + " · " + (links[value.link] || value.link);
}
function describePath(hops) {
  return hops.map((hop, index) => describeHop(hop, index, hops.length)).join(" → ");
}
function preview() {
  const rows = [...relayRows, exitRow].filter((item) => item?.node.value);
  const parts = rows.map((item) => {
    const role = item === exitRow ? "出口" : "中继";
    return role + " " + nodeName(item.node.value) + " · " + (links[item.link.value] || "待选连接方式");
  });
  get("preview").textContent = parts.length ? "本机 → " + parts.join(" → ") : "";
  get("preview").hidden = !parts.length;
}
function formHops() {
  if (!exitRow.node.value) throw new Error("请选择出口。");
  return [...relayRows, exitRow].map((item, index) => {
    if (!item.node.value) throw new Error("请选择第 " + (index + 1) + " 个中继。");
    if (!item.link.value) throw new Error("请选择 " + nodeName(item.node.value) + " 的连接方式。");
    return item.node.value + "@" + item.link.value;
  });
}
function updateListenHint() {
  get("listen").placeholder = settings?.socks5_default_listen || "留空使用默认地址";
  get("listen-hint").textContent = editing ? "切换路径时保留当前监听地址。"
    : settings?.socks5_allowed_sources?.length ? "可填写 0.0.0.0:1080 或指定本机 IP 和端口。端口填 0 可自动分配。"
    : settings ? "当前仅允许本机监听。监听其他地址需配置 client.allowed_sources。" : "";
}
function edit(route = null) {
  editing = route;
  get("edit-title").textContent = route ? "切换路径" : "新建路径";
  get("save").textContent = route ? "保存切换" : "创建路径";
  get("name").value = route?.name || "";
  get("name").readOnly = Boolean(route);
  get("listen").value = route?.listen || "";
  get("listen").readOnly = Boolean(route);
  updateListenHint();
  exitRow = hopRow("exit", route?.hops.at(-1));
  get("exit").replaceChildren(exitRow.row);
  relayRows = (route?.hops.slice(0, -1) || []).map((hop) => hopRow("relay", hop));
  renderRelays();
}
function renderRoutes(routes) {
  const body = get("routes");
  body.replaceChildren();
  if (!routes.length) {
    const cell = body.insertRow().insertCell();
    cell.colSpan = 4;
    cell.className = "muted";
    cell.textContent = "暂无已保存路径";
  }
  for (const route of routes) {
    const row = body.insertRow();
    row.insertCell().textContent = route.name;
    row.insertCell().textContent = route.listen;
    const path = row.insertCell();
    path.textContent = describePath(route.hops);
    path.title = route.hops.join(" → ");
    const actions = row.insertCell();
    const remove = button("删除", () => attempt(() => deleteRoute(route)));
    remove.className = "danger";
    actions.append(button("切换", () => { edit(route); exitRow.node.focus(); }), " ",
      button("测试", () => selectTestRoute(route)), " ", remove);
  }
  if (testing && !routes.some((route) => route.name === testing.name)) closeTest();
}
function renderDirectory(data) {
  directory = data;
  get("directory-status").textContent = data.ready ? "节点来自 Gossip 公告。" : "Gossip 目录暂不可用。";
  for (const [key, role] of [["exits", "exit"], ["relays", "relay"]]) {
    const list = get("directory-" + key);
    list.replaceChildren();
    if (!directory[key].length && data.ready) {
      list.append(textElement("li", role === "exit" ? "未发现可选出口" : "未发现可选中继", "muted"));
    }
    for (const candidate of directory[key]) {
      const value = selector(candidate);
      const row = document.createElement("li");
      const title = textElement("strong", nodeName(value));
      title.title = value;
      const details = ["连接方式 " + candidate.links.map((code) => links[code] || code).join(" / ")];
      if (role === "exit" && !candidate.discoverable) details.push("目标范围未公告");
      const info = document.createElement("div");
      info.append(title, textElement("p", details.join(" · "), "muted"));
      row.append(info, button(role === "exit" ? "选为出口" : "添加到路径", () => attempt(() => {
        if (role === "exit") { exitRow.choose(value); preview(); }
        else addRelay(value);
      })));
      list.append(row);
    }
  }
  exitRow.refresh();
  relayRows.forEach((item) => item.refresh());
  preview();
}
async function refresh() {
  const [routes, peers, admin] = await Promise.all([api("/v1/routes"), api("/v1/endpoints"), api("/v1/admin")]);
  settings = admin;
  updateListenHint();
  renderDirectory(peers);
  renderRoutes(routes);
  status("");
}
async function deleteRoute(route) {
  if (!window.confirm("删除「" + route.name + "」并关闭它的 SOCKS5 入口？")) return;
  await api("/v1/routes/" + encodeURIComponent(route.name), "DELETE");
  if (editing?.name === route.name) edit();
  if (testing?.name === route.name) closeTest();
  await refresh();
  status("已删除路径 " + route.name + "。");
}
function selectTestRoute(route) {
  closeTest();
  testing = route;
  get("route-test").hidden = false;
  get("test-title").textContent = "测试 " + route.name + " · " + route.listen;
  document.querySelector("[data-probe=connectivity]").focus();
}
const probeButtons = document.querySelectorAll("[data-probe], #probe");
function setProbing(busy) {
  for (const button of probeButtons) button.disabled = busy;
}
function closeTest() {
  pendingProbe?.abort();
  pendingProbe = null;
  setProbing(false);
  testing = null;
  get("route-test").hidden = true;
  get("result").textContent = "";
}
function probeSummary(kind, result) {
  if (!result.ok) {
    const hop = result.failed_hop === undefined ? "" : " · 第 " + (result.failed_hop + 1) + " 跳";
    return "测试失败" + hop + " · " + result.error;
  }
  const total = result.elapsed_ms + " ms";
  switch (kind) {
    case "connectivity": return "HTTP " + result.http_status + " · " + total;
    case "dns": return "DNS 查询成功 · " + total;
    case "download":
      return (result.bytes / 1048576).toFixed(2) + " MiB · " + result.download_mbps.toFixed(2) + " Mbps · 总耗时 " + total;
    default: return "连接成功 · " + total;
  }
}
async function probe(request) {
  const route = testing;
  if (!route || pendingProbe) return;
  const controller = new AbortController();
  pendingProbe = controller;
  setProbing(true);
  get("result").textContent = "正在测试 " + route.name + "…";
  try {
    const result = await api("/v1/routes/" + encodeURIComponent(route.name) + "/probe", "POST", request, controller.signal);
    if (pendingProbe === controller) get("result").textContent = probeSummary(request.kind, result);
  } catch (error) {
    if (pendingProbe === controller) get("result").textContent = error.message;
  } finally {
    if (pendingProbe === controller) {
      pendingProbe = null;
      setProbing(false);
    }
  }
}
async function attempt(action) {
  try { await action(); } catch (error) { status(error.message); }
}
get("auth").addEventListener("submit", (event) => {
  event.preventDefault();
  token = get("token").value.trim();
  get("token").value = "";
  attempt(refresh);
});
get("refresh").onclick = () => attempt(refresh);
get("add-relay").onclick = () => attempt(() => addRelay());
get("reset").onclick = () => edit();
get("close-test").onclick = closeTest;
for (const button of document.querySelectorAll("[data-probe]")) button.onclick = () => probe({ kind: button.dataset.probe });
get("custom-probe").addEventListener("submit", (event) => {
  event.preventDefault();
  const target = get("target").value.trim();
  if (target) probe({ protocol: get("protocol").value, target });
});
get("protocol").addEventListener("change", () => {
  get("target").placeholder = get("protocol").value === "udp" ? "例如 1.1.1.1:53" : "例如 192.168.50.10:443";
});
get("route-form").addEventListener("submit", (event) => {
  event.preventDefault();
  attempt(async () => {
    const body = { hops: formHops() };
    if (editing) {
      if (editing.udp_prefixes?.length) body.udp_prefixes = editing.udp_prefixes;
      await api("/v1/routes/" + encodeURIComponent(editing.name), "PUT", body);
      if (testing?.name === editing.name) closeTest();
    } else {
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

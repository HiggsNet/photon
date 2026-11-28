const get = (id) => document.getElementById(id);
const links = { h24: "公网 IPv4", h26: "公网 IPv6", h2p: "Photon Mesh", h2l4: "Photon IPsec 直连 IPv4", h2l6: "Photon IPsec 直连 IPv6" };
const aliases = { "public-v4": "h24", "public-v6": "h26", photon: "h2p", "link-local-v4": "h2l4", "link-local-v6": "h2l6" };
const relayLimit = 7;
let token = "";
let directory = { origin: "", ready: false, exits: [], relays: [] };
let settings = null;
let editing = null;
let testing = null;
let pendingProbe = null;
let saving = false;
let exitRow;
let relayRows = [];
const editor = get("route-editor");

function status(message) {
  get("status").textContent = editor.open ? "" : message;
  get("editor-status").textContent = editor.open ? message : "";
}
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

function compareText(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}
function compareNodes(a, b) {
  const left = a.zone.split(/[.-]/).filter(Boolean).reverse();
  const right = b.zone.split(/[.-]/).filter(Boolean).reverse();
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    const order = compareText(left[i], right[i]);
    if (order) return order;
  }
  return left.length - right.length || compareText(a.zone, b.zone) || compareText(a.endpoint, b.endpoint);
}

function hopRow(role, hop = "") {
  const initial = splitHop(hop);
  const row = document.createElement("div");
  row.className = "hop";
  const node = document.createElement("select");
  node.className = "node-select";
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
      node.append(new Option(value, value));
    }
    if (selected && ![...node.options].some((option) => option.value === selected)) {
      node.append(new Option(selected + "（目录未提供）", selected));
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
  item.nodeLabel = textElement("span", role === "exit" ? "出口节点" : "中继节点");
  row.append(field(item.nodeLabel, node), field("连接方式", link));
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
    item.up = button("↑", () => move(-1));
    item.down = button("↓", () => move(1));
    for (const [control, label] of [[item.up, "上移"], [item.down, "下移"]]) {
      control.title = label;
      control.setAttribute("aria-label", label);
    }
    const remove = button("移除", () => {
      relayRows = relayRows.filter((candidate) => candidate !== item);
      renderRelays();
      get("add-relay").focus();
    });
    remove.className = "danger";
    actions.append(item.up, item.down, remove);
    row.append(actions);
  }
  renderNodes(initial.node, initial.link);
  return item;
}
function renderRelays() {
  for (const [index, row] of relayRows.entries()) {
    row.nodeLabel.textContent = "中继 " + (index + 1);
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
  get("edit-title").textContent = route ? "调整路径" : "新建路径";
  get("save").textContent = route ? "保存路径" : "创建路径";
  get("reset").textContent = route ? "取消" : "清空";
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
function openEditor(route = null) {
  edit(route);
  editor.showModal();
  status("");
  get(route ? "edit-title" : "name").focus();
}
function renderRoutes(routes) {
  const body = get("routes");
  const testPanel = get("route-test");
  body.after(testPanel);
  body.replaceChildren();
  get("empty-routes").hidden = routes.length > 0;
  for (const route of routes) {
    const card = textElement("li", "", "route-card");
    const head = textElement("div", "", "route-head");
    const identity = textElement("div", "", "route-identity");
    identity.append(textElement("h3", route.name), textElement("code", route.listen));
    const actions = textElement("div", "", "line route-actions");
    const remove = button("删除", () => attempt(() => deleteRoute(route)));
    remove.className = "danger";
    actions.append(button("调整", () => openEditor(route)),
      button("测试", () => selectTestRoute(route, card)), remove);
    head.append(identity, actions);
    const path = textElement("ol", "", "route-hops");
    for (const [index, hop] of route.hops.entries()) {
      const value = splitHop(hop);
      const end = index === route.hops.length - 1;
      const step = textElement("li", "", end ? "step exit-step" : "step");
      step.title = hop;
      step.append(textElement("small", end ? "出口" : "中继 " + (index + 1)),
        textElement("strong", nodeName(value.node)),
        textElement("small", links[value.link] || value.link));
      path.append(step);
    }
    card.append(head, path);
    if (testing?.name === route.name) card.append(testPanel);
    body.append(card);
  }
  if (testing && !routes.some((route) => route.name === testing.name)) closeTest();
}
function renderDirectory(data) {
  directory = { ...data, exits: [...data.exits].sort(compareNodes), relays: [...data.relays].sort(compareNodes) };
  get("directory-status").textContent = data.ready ? "" : "Gossip 目录暂不可用。";
  for (const [key, role] of [["exits", "exit"], ["relays", "relay"]]) {
    const list = get("directory-" + key);
    list.replaceChildren();
    if (!directory[key].length && data.ready) {
      list.append(textElement("li", role === "exit" ? "未发现可选出口" : "未发现可选中继", "muted"));
    }
    for (const candidate of directory[key]) {
      const value = selector(candidate);
      const row = document.createElement("li");
      const title = textElement("strong", value);
      const details = [candidate.links.map((code) => links[code] || code).join(" / ")];
      if (role === "exit" && !candidate.discoverable) details.push("目标范围未公告");
      const info = document.createElement("div");
      info.append(title, textElement("p", details.join(" · "), "muted"));
      row.append(button(role === "exit" ? "选为出口" : "加入中继", () => attempt(() => {
        if (role === "exit") { exitRow.choose(value); preview(); }
        else addRelay(value);
      })), info);
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
function selectTestRoute(route, card) {
  closeTest();
  testing = route;
  const panel = get("route-test");
  card.append(panel);
  panel.hidden = false;
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
  showResult("");
}
function showResult(message, state = "") {
  const result = get("result");
  result.textContent = message;
  result.dataset.state = state;
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
      return result.download_mbps.toFixed(2) + " Mbps · " + (result.bytes / 1048576).toFixed(2) + " MiB · 总耗时 " + total;
    default: return "连接成功 · " + total;
  }
}
async function probe(request) {
  const route = testing;
  if (!route || pendingProbe) return;
  const controller = new AbortController();
  pendingProbe = controller;
  setProbing(true);
  showResult("正在测试 " + route.name + "…", "pending");
  try {
    const result = await api("/v1/routes/" + encodeURIComponent(route.name) + "/probe", "POST", request, controller.signal);
    if (pendingProbe === controller) showResult(probeSummary(request.kind, result), result.ok ? "success" : "error");
  } catch (error) {
    if (pendingProbe === controller) showResult(error.message, "error");
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
get("new-route").onclick = () => openEditor();
get("close-editor").onclick = () => { if (!saving) editor.close(); };
editor.addEventListener("cancel", (event) => { if (saving) event.preventDefault(); });
get("add-relay").onclick = () => attempt(() => addRelay());
get("reset").onclick = () => {
  if (saving) return;
  if (editing) editor.close();
  else {
    edit();
    status("");
    get("name").focus();
  }
};
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
  if (saving) return;
  attempt(async () => {
    const body = { hops: formHops() };
    saving = true;
    get("save").disabled = true;
    try {
      if (editing) {
        if (editing.udp_prefixes?.length) body.udp_prefixes = editing.udp_prefixes;
        await api("/v1/routes/" + encodeURIComponent(editing.name), "PUT", body);
        if (testing?.name === editing.name) closeTest();
      } else {
        body.name = get("name").value.trim();
        body.listen = get("listen").value.trim();
        await api("/v1/routes", "POST", body);
      }
      editor.close();
      edit();
      await refresh();
      status("已保存路径。");
    } finally {
      saving = false;
      get("save").disabled = false;
    }
  });
});
edit();
attempt(refresh);

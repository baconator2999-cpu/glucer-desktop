const { app, BrowserWindow, shell, session, dialog, ipcMain } = require("electron");
const path = require("path");
const fs = require("fs");
const fsp = fs.promises;
const os = require("os");

const START_URL = "https://glucer.com/chat.html";
const ALLOWED_HOSTS = ["glucer.com", "www.glucer.com", "glucer.netlify.app"];

function isAllowed(url) {
  try {
    const u = new URL(url);
    return u.protocol === "https:" && ALLOWED_HOSTS.includes(u.hostname);
  } catch (e) { return false; }
}

// Only real web links may be handed to the operating system.
// file://, ms-msdt:, search-ms: and any app-registered scheme:// are dropped.
function safeToOpen(url) {
  try { return /^https?:$/.test(new URL(url).protocol); } catch (e) { return false; }
}

let win = null;
let config = {};
let allowAll = false; // "don't ask again", lasts only until the app closes

const configFile = () => path.join(app.getPath("userData"), "glucer-config.json");
function loadConfig() { try { config = JSON.parse(fs.readFileSync(configFile(), "utf8")) || {}; } catch (e) { config = {}; } }
function saveConfig() { try { fs.writeFileSync(configFile(), JSON.stringify(config)); } catch (e) {} }

/* ---------- Safe file tools ---------- */
class ToolError extends Error {}
const MAX_LIST = 500, MAX_FIND = 200, MAX_READ = 20000;
const BLOCKED_WRITE = /\.(exe|bat|cmd|com|command|msi|scr|vbs|ps1|psm1|dll|lnk|jar|reg|hta|wsf|jse|vbe|sh|url|desktop|application|appx|msix)$/i;
const SECRET_NAMES = /(^|[\\/])(\.env[^\\/]*|\.netrc|\.git-credentials|\.npmrc|\.aws([\\/].*)?|id_rsa[^\\/]*|id_ed25519[^\\/]*|id_ecdsa[^\\/]*|[^\\/]*\.(pem|key|pfx|p12|kdbx|jks)|[^\\/]*password[^\\/]*|[^\\/]*secret[^\\/]*|[^\\/]*credential[^\\/]*)$/i;

function wsRoot() {
  if (!config.workspace) throw new ToolError("NO_WORKSPACE: No folder has been chosen. Ask the user to click the folder button and pick one.");
  try { return fs.realpathSync(config.workspace); }
  catch (e) { throw new ToolError("NO_WORKSPACE: The chosen folder is missing. Ask the user to choose it again."); }
}

// Resolve the part of a path that exists (following shortcuts), then add the rest
function realpathLoose(p) {
  let cur = p;
  const rest = [];
  while (!fs.existsSync(cur)) {
    rest.unshift(path.basename(cur));
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return path.join(fs.realpathSync(cur), ...rest);
}

// Every path must end up inside the chosen folder, or the tool refuses
function resolveInside(p) {
  const root = wsRoot();
  const abs = path.resolve(root, String(p === undefined || p === null || p === "" ? "." : p));
  const real = realpathLoose(abs);
  const r = path.relative(root, real);
  if (r === ".." || r.startsWith(".." + path.sep) || path.isAbsolute(r)) throw new ToolError("That path is outside the folder Glucer can use.");
  return real;
}
const rel = (abs) => path.relative(wsRoot(), abs) || ".";
const denied = () => ({ denied: true, result: { error: "The user declined this action." }, summary: "You declined this action" });

// Approval pop-up. It's drawn by the app itself, so a web page can't fake or skip it.
async function approve(title, detail) {
  if (allowAll) return true;
  const r = await dialog.showMessageBox(win, {
    type: "question", buttons: ["Allow", "Deny"], defaultId: 1, cancelId: 1, noLink: true,
    title: "Glucer wants to change files", message: title, detail,
    checkboxLabel: "Don't ask again for the rest of this session", checkboxChecked: false
  });
  if (r.response !== 0) return false;
  if (r.checkboxChecked) allowAll = true;
  return true;
}

async function listFolder(args) {
  const dir = resolveInside(args.path || ".");
  const st = await fsp.stat(dir);
  if (!st.isDirectory()) throw new ToolError("That's not a folder.");
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  const items = [];
  for (const d of entries.slice(0, MAX_LIST)) {
    let size = null, modified = null;
    try {
      const s = await fsp.stat(path.join(dir, d.name));
      size = d.isDirectory() ? null : s.size;
      modified = s.mtime.toISOString().slice(0, 10);
    } catch (e) {}
    items.push({ name: d.name, type: d.isDirectory() ? "folder" : "file", size, modified });
  }
  return { result: { path: rel(dir), count: entries.length, shown: items.length, items }, summary: "Looked in " + rel(dir) + " (" + entries.length + " items)" };
}

async function findFiles(args) {
  const start = resolveInside(args.path || ".");
  const q = String(args.query || "").toLowerCase().trim();
  if (!q) throw new ToolError("Nothing to search for.");
  const out = [];
  let visited = 0;
  async function walk(dir, depth) {
    if (out.length >= MAX_FIND || depth > 6 || visited > 20000) return;
    let entries;
    try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const d of entries) {
      visited++;
      if (d.isSymbolicLink()) continue;
      const full = path.join(dir, d.name);
      if (d.name.toLowerCase().includes(q)) out.push({ path: rel(full), type: d.isDirectory() ? "folder" : "file" });
      if (out.length >= MAX_FIND) return;
      if (d.isDirectory()) await walk(full, depth + 1);
    }
  }
  await walk(start, 0);
  return { result: { matches: out, truncated: out.length >= MAX_FIND }, summary: 'Searched for "' + q + '" (' + out.length + " found)" };
}

async function readTextFile(args) {
  const f = resolveInside(args.path);
  if (SECRET_NAMES.test(f)) throw new ToolError("That file looks like it holds passwords or keys, so Glucer won't read it.");
  const st = await fsp.stat(f);
  if (!st.isFile()) throw new ToolError("That's not a file.");
  if (st.size > 5 * 1024 * 1024) throw new ToolError("That file is too large to read.");
  const buf = await fsp.readFile(f);
  if (buf.includes(0)) throw new ToolError("That looks like a binary file, not text.");
  const text = buf.toString("utf8");
  return { result: { path: rel(f), content: text.slice(0, MAX_READ), truncated: text.length > MAX_READ }, summary: "Read " + rel(f) };
}

async function createFolders(args) {
  const list = (Array.isArray(args.paths) ? args.paths : []).slice(0, 200).map((p) => resolveInside(p));
  if (!list.length) throw new ToolError("No folders were given.");
  const lines = list.slice(0, 12).map((p) => rel(p));
  if (list.length > 12) lines.push("...and " + (list.length - 12) + " more");
  if (!(await approve("Create " + list.length + (list.length === 1 ? " folder" : " folders"), lines.join("\n")))) return denied();
  for (const p of list) await fsp.mkdir(p, { recursive: true });
  return { result: { created: list.map(rel) }, summary: "Created " + list.length + (list.length === 1 ? " folder" : " folders") };
}

async function moveItems(args) {
  const root = wsRoot();
  const moves = (Array.isArray(args.moves) ? args.moves : []).slice(0, 500);
  if (!moves.length) throw new ToolError("No moves were given.");
  const plan = moves.map((m) => ({ from: resolveInside(m.from), to: resolveInside(m.to) }));
  // Same guardrails as writes apply to renames: no turning files into
  // program types, and no renaming to or from secret-looking names to
  // slip past the read filter.
  for (const p of plan) {
    if (BLOCKED_WRITE.test(p.to)) throw new ToolError("Glucer won't rename files into program types like that.");
    if (SECRET_NAMES.test(p.from) !== SECRET_NAMES.test(p.to)) throw new ToolError("Glucer won't rename files to or from secret-looking names.");
  }
  const dests = new Set();
  for (const p of plan) {
    if (p.from === root || p.to === root) throw new ToolError("Glucer can't move the workspace folder itself.");
    if (!fs.existsSync(p.from)) throw new ToolError("Not found: " + rel(p.from));
    if (fs.existsSync(p.to)) throw new ToolError("Already exists (Glucer never overwrites): " + rel(p.to));
    if (dests.has(p.to)) throw new ToolError("Two files would end up at the same place: " + rel(p.to));
    dests.add(p.to);
  }
  const lines = plan.slice(0, 12).map((p) => rel(p.from) + "  ->  " + rel(p.to));
  if (plan.length > 12) lines.push("...and " + (plan.length - 12) + " more");
  if (!(await approve("Move " + plan.length + (plan.length === 1 ? " item" : " items"), lines.join("\n")))) return denied();
  let done = 0;
  const errors = [];
  for (const p of plan) {
    try { await fsp.mkdir(path.dirname(p.to), { recursive: true }); await fsp.rename(p.from, p.to); done++; }
    catch (e) { errors.push(rel(p.from) + ": " + (e.code || "failed")); }
  }
  return { result: { moved: done, errors }, summary: "Moved " + done + (done === 1 ? " item" : " items") + (errors.length ? " (" + errors.length + " failed)" : "") };
}

async function writeTextFile(args) {
  const f = resolveInside(args.path);
  if (BLOCKED_WRITE.test(f)) throw new ToolError("Glucer won't create program or script files like that.");
  const content = String(args.content === undefined ? "" : args.content);
  if (content.length > 200000) throw new ToolError("That content is too large.");
  const exists = fs.existsSync(f);
  if (exists && fs.statSync(f).isDirectory()) throw new ToolError("That path is a folder.");
  if (exists && args.overwrite !== true) throw new ToolError("That file already exists. Ask the user before replacing it, then set overwrite to true.");
  const detail = (exists ? "This REPLACES the existing file:\n" : "") + rel(f) + "\n(" + content.length + " characters)";
  if (!(await approve(exists ? "Replace a file" : "Create a file", detail))) return denied();
  await fsp.mkdir(path.dirname(f), { recursive: true });
  await fsp.writeFile(f, content, "utf8");
  return { result: { written: rel(f) }, summary: (exists ? "Replaced " : "Created ") + rel(f) };
}

async function trashItems(args) {
  const root = wsRoot();
  const list = (Array.isArray(args.paths) ? args.paths : []).slice(0, 200).map((p) => resolveInside(p));
  if (!list.length) throw new ToolError("No items were given.");
  for (const p of list) {
    if (p === root) throw new ToolError("Glucer can't trash the workspace folder itself.");
    if (!fs.existsSync(p)) throw new ToolError("Not found: " + rel(p));
  }
  const lines = list.slice(0, 12).map((p) => rel(p));
  if (list.length > 12) lines.push("...and " + (list.length - 12) + " more");
  const title = "Move " + list.length + (list.length === 1 ? " item" : " items") + " to the Recycle Bin / Trash";
  if (!(await approve(title, lines.join("\n") + "\n\nYou can restore them from the Recycle Bin / Trash."))) return denied();
  let done = 0;
  const errors = [];
  for (const p of list) {
    try { await shell.trashItem(p); done++; } catch (e) { errors.push(rel(p)); }
  }
  return { result: { trashed: done, failed: errors }, summary: "Moved " + done + (done === 1 ? " item" : " items") + " to the Trash" + (errors.length ? " (" + errors.length + " failed)" : "") };
}

async function revealItem(args) {
  const f = resolveInside(args.path);
  shell.showItemInFolder(f);
  return { result: { shown: rel(f) }, summary: "Showed " + rel(f) };
}

const TOOL_FUNCS = {
  list_folder: listFolder, find_files: findFiles, read_text_file: readTextFile, create_folders: createFolders,
  move_items: moveItems, write_text_file: writeTextFile, trash_items: trashItems, reveal_item: revealItem
};

/* ---------- Bridge for the Glucer page (only trusted pages may call it) ---------- */
function trusted(event) {
  try { const f = event.senderFrame; return !!f && f.parent === null && isAllowed(f.url); }
  catch (e) { return false; }
}
const wsInfo = () => (config.workspace ? { name: path.basename(config.workspace) } : null);

ipcMain.handle("ws:get", (event) => (trusted(event) ? { ok: true, workspace: wsInfo() } : { ok: false, error: "Not allowed" }));

ipcMain.handle("ws:clear", (event) => {
  if (!trusted(event)) return { ok: false, error: "Not allowed" };
  delete config.workspace; saveConfig(); allowAll = false;
  return { ok: true, workspace: null };
});

ipcMain.handle("ws:choose", async (event) => {
  if (!trusted(event)) return { ok: false, error: "Not allowed" };
  const r = await dialog.showOpenDialog(win, { title: "Choose the one folder Glucer can work in", properties: ["openDirectory"], buttonLabel: "Use this folder" });
  if (r.canceled || !r.filePaths[0]) return { ok: true, workspace: wsInfo() };
  let p;
  try { p = fs.realpathSync(r.filePaths[0]); } catch (e) { return { ok: false, error: "Couldn't open that folder." }; }
  const parsed = path.parse(p);
  if (parsed.root === p || parsed.dir === parsed.root || p === os.homedir()) {
    return { ok: false, error: "Pick a specific folder, like Downloads or a project folder, not a whole drive or your entire home folder." };
  }
  config.workspace = p; saveConfig(); allowAll = false;
  return { ok: true, workspace: wsInfo() };
});

ipcMain.handle("tool:run", async (event, name, args) => {
  if (!trusted(event)) return { ok: false, error: "Not allowed" };
  const fn = TOOL_FUNCS[name];
  if (!fn) return { ok: false, error: "Unknown tool.", summary: "Unknown action" };
  try {
    const r = await fn(args && typeof args === "object" ? args : {});
    return Object.assign({ ok: !r.denied }, r);
  } catch (e) {
    const msg = e instanceof ToolError ? e.message : "Something went wrong (" + (e.code || e.message) + ").";
    return { ok: false, error: msg, summary: "Couldn't finish: " + msg };
  }
});

/* ---------- Window ---------- */

const glucerAgent = require("./glucer-agent.js");
const glucerExtras = require("./glucer-extras.js");
ipcMain.handle("glucer2:call", (event, name, args, approved, readOnly) => {
  const url = (event.senderFrame && event.senderFrame.url) || "";
  if (!isAllowed(url)) return { ok: false, error: "That page isn't allowed to use Computer access." };
  return glucerAgent.handleCall(String(name), args, approved === true, readOnly === true);
});

function createWindow() {
  win = new BrowserWindow({
    glucerExtras.attach(win);
    width: 1200, height: 800, minWidth: 420, minHeight: 600,
    backgroundColor: "#1E1530", title: "Glucer", show: false, autoHideMenuBar: true,
    icon: path.join(__dirname, "build", "icon.png"),
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: true, backgroundThrottling: false }
  });

  // Lets the website know it's running inside the desktop app
  win.webContents.setUserAgent(win.webContents.getUserAgent() + " GlucerDesktop/" + app.getVersion());

  win.once("ready-to-show", () => win.show());
  win.loadURL(START_URL);

  // Popups never open inside the app; only real http/https links may be
  // handed to the system browser.
  win.webContents.setWindowOpenHandler(({ url }) => { if (safeToOpen(url)) shell.openExternal(url); return { action: "deny" }; });
  win.webContents.on("will-navigate", (e, url) => {
    if (isAllowed(url)) return;
    e.preventDefault();
    if (safeToOpen(url)) shell.openExternal(url);
  });

  // No internet: show a friendly page instead of a blank window
  win.webContents.on("did-fail-load", (e, code, desc, url, isMainFrame) => {
    if (isMainFrame && code !== -3) win.loadFile(path.join(__dirname, "offline.html"));
  });

  win.on("closed", () => { win = null; });
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (win) { if (win.isMinimized()) win.restore(); win.show(); win.focus(); }
  });
  app.whenReady().then(() => {
    loadConfig();
    glucerExtras.setup();
    session.defaultSession.setPermissionRequestHandler((wc, permission, callback, details) => {
      const ok = isAllowed(details.requestingUrl || "") && ["clipboard-sanitized-write", "fullscreen", "notifications"].includes(permission);
      callback(ok);
    });
    createWindow();
    app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
}

app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });

const { app, BrowserWindow, shell, session, ipcMain, Menu } = require("electron");

// No menu "taskbar" at the top of the window (File/Edit/View/etc.).
// The chat page is the whole app; nothing else belongs above it.
Menu.setApplicationMenu(null);
const path = require("path");
const fs = require("fs");

const START_URL = "https://glucer-chat.baconator2999.workers.dev/app.html";
const ALLOWED_HOSTS = ["glucer.com", "www.glucer.com", "glucer.netlify.app", "glucer-chat.baconator2999.workers.dev"];

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

// "Allow always on everything" lives in config.allowEverything and is saved to
// disk, so it really is forever. When it is on, every action runs right away.
// When it is off, the Glucer chat window shows its own approval card (sliding
// up from above the chat bar) and calls back through here with approved=true.
// This app never opens native Windows dialogs for approvals.

const configFile = () => path.join(app.getPath("userData"), "glucer-config.json");
function loadConfig() { try { config = JSON.parse(fs.readFileSync(configFile(), "utf8")) || {}; } catch (e) { config = {}; } }
function saveConfig() { try { fs.writeFileSync(configFile(), JSON.stringify(config)); } catch (e) {} }

/* ---------- Bridge for the Glucer page (only trusted pages may call it) ---------- */
function trusted(event) {
  try { const f = event.senderFrame; return !!f && f.parent === null && isAllowed(f.url); }
  catch (e) { return false; }
}

const glucerAgent = require("./glucer-agent.js");
const glucerExtras = require("./glucer-extras.js");

ipcMain.handle("glucer2:call", async (event, name, args, approved, readOnly) => {
  const url = (event.senderFrame && event.senderFrame.url) || "";
  if (!isAllowed(url)) return { ok: false, error: "That page isn't allowed to use Computer access." };
  name = String(name);
  let r = await glucerAgent.handleCall(name, args, approved === true, readOnly === true);
  // Two paths, no native dialogs:
  //  - "Allow always on everything" is on -> every action runs right away.
  //  - otherwise -> the chat window shows its own approval card and calls
  //    back through here with approved=true (or not at all if declined).
  if (r && r.needsApproval && config.allowEverything) {
    r = await glucerAgent.handleCall(name, args, true, readOnly === true);
  }
  return r;
});

ipcMain.handle("glucer2:get-allow-all", (event) => {
  if (!trusted(event)) return { ok: false, on: false };
  return { ok: true, on: !!config.allowEverything };
});

ipcMain.handle("glucer2:set-allow-all", (event, on) => {
  if (!trusted(event)) return { ok: false, error: "Not allowed" };
  config.allowEverything = on === true;
  saveConfig();
  return { ok: true, on: config.allowEverything };
});

// The chat page knows the live theme colors; it sends them here so the
// native min/max/close buttons always match the strip below them
// (light or dark, any color scheme). Only hex/rgb strings are accepted.
ipcMain.handle("glucer2:titlebar-colors", (event, colors) => {
  if (!trusted(event)) return { ok: false };
  try {
    const okColor = (v) => (typeof v === "string" && /^(#[0-9a-fA-F]{3,8}|rgb)/.test(v.trim()) ? v.trim() : null);
    const opts = {};
    const bar = okColor(colors && colors.bar); if (bar) opts.color = bar;
    const sym = okColor(colors && colors.symbol); if (sym) opts.symbolColor = sym;
    if (Object.keys(opts).length && win && !win.isDestroyed()) win.setTitleBarOverlay(opts);
    return { ok: true };
  } catch (e) { return { ok: false }; }
});

// The chat page draws its own min/max/close buttons (themed to match the
// window). This is where those buttons land.
ipcMain.handle("glucer2:win-control", (event, action) => {
  if (!trusted(event)) return { ok: false };
  if (!win || win.isDestroyed()) return { ok: false };
  action = String(action || "");
  if (action === "minimize") win.minimize();
  else if (action === "maximize") { if (win.isMaximized() || win.isFullScreen()) win.unmaximize(); else win.maximize(); }
  else if (action === "close") win.close(); // goes to the tray, same as clicking X
  else return { ok: false };
  return { ok: true };
});

/* ---------- Window ---------- */

function createWindow() {
  win = new BrowserWindow({
    width: 1200, height: 800, minWidth: 420, minHeight: 600,
    backgroundColor: "#1E1530", title: "Glucer", show: false, autoHideMenuBar: true,
    // Frameless: no title bar strip at the top, and NO native min/max/close
    // buttons (those always showed up white on Windows). The chat page draws
    // its own window buttons in the exact theme colors instead, and calls
    // back through glucer2:win-control to minimize / maximize / close.
    titleBarStyle: "hidden",
    icon: path.join(__dirname, "build", "icon.png"),
    webPreferences: { preload: path.join(__dirname, "preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: true, backgroundThrottling: false }
  });
  glucerExtras.attach(win);

  // Lets the website know it's running inside the desktop app
  win.webContents.setUserAgent(win.webContents.getUserAgent() + " GlucerDesktop/" + app.getVersion());

  win.once("ready-to-show", () => win.show());
  // Add a fresh version tag on every launch so the app always loads the newest
  // chat page from the website instead of a saved old copy (cache).
  win.loadURL(START_URL + (START_URL.includes("?") ? "&" : "?") + "v=" + Date.now());

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
      const ok = isAllowed(details.requestingUrl || "") && ["clipboard-sanitized-write", "fullscreen", "notifications", "media"].includes(permission);
      callback(ok);
    });
    createWindow();
    app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
}

app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });

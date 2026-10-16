const { app, BrowserWindow, shell, session } = require("electron");
const path = require("path");

const START_URL = "https://glucer.com/chat.html";
const ALLOWED_HOSTS = ["glucer.com", "www.glucer.com", "glucer.netlify.app"];

function isAllowed(url) {
  try {
    const u = new URL(url);
    return u.protocol === "https:" && ALLOWED_HOSTS.includes(u.hostname);
  } catch (e) { return false; }
}

let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: 1200, height: 800, minWidth: 420, minHeight: 600,
    backgroundColor: "#1E1530", title: "Glucer", show: false, autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true }
  });

  // Lets the website know it's running inside the desktop app
  win.webContents.setUserAgent(win.webContents.getUserAgent() + " GlucerDesktop/" + app.getVersion());

  win.once("ready-to-show", () => win.show());
  win.loadURL(START_URL);

  // Anything outside Glucer (checkout, links) opens in the normal browser
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: "deny" }; });
  win.webContents.on("will-navigate", (e, url) => {
    if (!isAllowed(url) && !url.startsWith("file://")) { e.preventDefault(); shell.openExternal(url); }
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
    if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
  });
  app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((wc, permission, callback, details) => {
      const ok = isAllowed(details.requestingUrl || "") && ["clipboard-sanitized-write", "fullscreen", "notifications"].includes(permission);
      callback(ok);
    });
    createWindow();
    app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  });
}

app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });

const { app, BrowserWindow, Tray, Menu, nativeImage, globalShortcut, ipcMain, Notification } = require("electron");
const path = require("path");

const HOTKEY = "CommandOrControl+Shift+Space";
let tray = null, quickWin = null, mainWin = null, quitting = false, hintShown = false;

function showMain() {
  if (!mainWin || mainWin.isDestroyed()) return;
  if (mainWin.isMinimized()) mainWin.restore();
  mainWin.show();
  mainWin.focus();
}
function hideQuick() { if (quickWin && !quickWin.isDestroyed()) quickWin.hide(); }

function openQuick() {
  if (quickWin && !quickWin.isDestroyed()) {
    quickWin.center(); quickWin.show(); quickWin.focus();
    quickWin.webContents.send("glucer2:quick-reset");
    return;
  }
  quickWin = new BrowserWindow({
    width: 640, height: 80, frame: false, resizable: false, alwaysOnTop: true, skipTaskbar: true, show: false,
    backgroundColor: "#1E1530", title: "Glucer quick ask",
    webPreferences: { preload: path.join(__dirname, "quick-preload.js"), contextIsolation: true, nodeIntegration: false, sandbox: true }
  });
  quickWin.loadFile(path.join(__dirname, "quick.html"));
  quickWin.once("ready-to-show", () => { quickWin.center(); quickWin.show(); quickWin.focus(); });
  quickWin.on("blur", hideQuick);
  quickWin.on("closed", () => { quickWin = null; });
}

function makeTray() {
  try {
    let img = nativeImage.createFromPath(path.join(__dirname, "build", "icon.png"));
    if (img.isEmpty()) return;
    img = img.resize({ width: 16, height: 16 });
    tray = new Tray(img);
    tray.setToolTip("Glucer");
    tray.on("click", showMain);
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: "Open Glucer", click: showMain },
      { label: "Quick ask (Ctrl+Shift+Space)", click: openQuick },
      { type: "separator" },
      { label: "Start Glucer when I sign in", type: "checkbox", checked: app.getLoginItemSettings().openAtLogin, click: (item) => app.setLoginItemSettings({ openAtLogin: item.checked }) },
      { type: "separator" },
      { label: "Quit Glucer", click: () => { quitting = true; app.quit(); } }
    ]));
  } catch (e) { tray = null; }
}

// Call once inside app.whenReady()
function setup() {
  if (process.platform === "win32") app.setAppUserModelId("com.glucer.desktop");
  makeTray();
  if (!globalShortcut.register(HOTKEY, openQuick)) console.log("The quick-ask shortcut is already used by another app.");
  app.on("before-quit", () => { quitting = true; });
  app.on("will-quit", () => globalShortcut.unregisterAll());

  ipcMain.on("glucer2:quick-submit", (e, text) => {
    if (!quickWin || e.sender !== quickWin.webContents) return;
    text = String(text || "").trim().slice(0, 6000);
    if (!text || !mainWin || mainWin.isDestroyed()) return;
    hideQuick(); showMain();
    mainWin.webContents.send("glucer2:quick", text);
  });
  ipcMain.on("glucer2:quick-close", (e) => { if (quickWin && e.sender === quickWin.webContents) hideQuick(); });
  ipcMain.on("glucer2:focus", (e) => { if (mainWin && e.sender === mainWin.webContents) showMain(); });
}

// Call right after the main window is created
function attach(win) {
  mainWin = win;
  win.on("session-end", () => { quitting = true; });
  win.on("close", (e) => {
    if (quitting || !tray) return; // without a tray icon, closing really closes
    e.preventDefault();
    win.hide();
    if (!hintShown && Notification.isSupported()) {
      hintShown = true;
      new Notification({ title: "Glucer is still running", body: "It's in your system tray so scheduled tasks can run. Right-click the tray icon to quit." }).show();
    }
  });
}

module.exports = { setup, attach };

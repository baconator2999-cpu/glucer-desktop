const { contextBridge, ipcRenderer, webUtils } = require("electron");

contextBridge.exposeInMainWorld("glucerDesktop", {
  runTool: (name, args, approved, readOnly) => ipcRenderer.invoke("glucer2:call", String(name), args || {}, approved === true, readOnly === true),
  getAllowAll: () => ipcRenderer.invoke("glucer2:get-allow-all"),
  setAllowAll: (on) => ipcRenderer.invoke("glucer2:set-allow-all", on === true),
  // The page's own minimize / maximize / close buttons (drawn in the theme
  // colors) call this. "close" goes to the tray, same as the old X button.
  winControl: (action) => ipcRenderer.invoke("glucer2:win-control", String(action || "")),
  // The page sends its live theme colors so the min/max/close buttons in the
  // top-right corner are painted the same color as the strip below them.
  setTitleBarColors: (colors) => ipcRenderer.invoke("glucer2:titlebar-colors", colors || {}),
  pathFor: (file) => { try { return webUtils.getPathForFile(file); } catch (e) { return ""; } },
  focusWindow: () => ipcRenderer.send("glucer2:focus"),
  onQuick: (cb) => { ipcRenderer.on("glucer2:quick", (e, text) => cb(String(text || ""))); },
  // Kept so older pages don't break. Glucer works with the whole computer.
  getWorkspace: async () => ({ workspace: { name: "This computer" } }),
  chooseWorkspace: async () => ({ ok: true, workspace: { name: "This computer" } })
});

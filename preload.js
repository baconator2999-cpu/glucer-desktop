const { contextBridge, ipcRenderer, webUtils } = require("electron");

contextBridge.exposeInMainWorld("glucerDesktop", {
  runTool: (name, args, approved, readOnly) => ipcRenderer.invoke("glucer2:call", String(name), args || {}, approved === true, readOnly === true),
  pathFor: (file) => { try { return webUtils.getPathForFile(file); } catch (e) { return ""; } },
  focusWindow: () => ipcRenderer.send("glucer2:focus"),
  onQuick: (cb) => { ipcRenderer.on("glucer2:quick", (e, text) => cb(String(text || ""))); },
  // Kept so older pages don't break. Glucer works with the whole computer.
  getWorkspace: async () => ({ workspace: { name: "This computer" } }),
  chooseWorkspace: async () => ({ ok: true, workspace: { name: "This computer" } })
});

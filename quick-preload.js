const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("quick", {
  submit: (t) => ipcRenderer.send("glucer2:quick-submit", String(t || "")),
  close: () => ipcRenderer.send("glucer2:quick-close"),
  onReset: (cb) => ipcRenderer.on("glucer2:quick-reset", () => cb())
});

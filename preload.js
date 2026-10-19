const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("glucerDesktop", {
  runTool: (name, args, approved) => ipcRenderer.invoke("glucer2:call", String(name), args || {}, approved === true),
  // Kept so older pages don't break. Glucer now works with the whole computer.
  getWorkspace: async () => ({ workspace: { name: "This computer" } }),
  chooseWorkspace: async () => ({ ok: true, workspace: { name: "This computer" } })
});

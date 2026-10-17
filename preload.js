const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("glucerDesktop", {
  version: 2,
  getWorkspace: () => ipcRenderer.invoke("ws:get"),
  chooseWorkspace: () => ipcRenderer.invoke("ws:choose"),
  clearWorkspace: () => ipcRenderer.invoke("ws:clear"),
  runTool: (name, args) => ipcRenderer.invoke("tool:run", String(name), args)
});

import { defineChannelPluginEntry, emptyPluginConfigSchema } from "openclaw/plugin-sdk/core";
import { registerWapCli, registerWapCommands, registerWapTools, startWsService, stopWsService, wapPlugin } from "./api.js";
import { setWapRuntime } from "./runtime-api.js";

export default defineChannelPluginEntry({
  id: "openclaw-channel-wap",
  name: "WeChat (WAP)",
  description: "WeChat channel via WAuxiliary plugin",
  configSchema: emptyPluginConfigSchema,
  plugin: wapPlugin,
  setRuntime: setWapRuntime,
  registerCliMetadata(api) {
    registerWapCli(api);
  },
  registerFull(api) {
    registerWapTools(api);
    registerWapCommands(api);
    api.registerService({
      id: "wap-ws-server",
      start: () => startWsService(api),
      stop: () => stopWsService(api.logger),
    });
  },
});

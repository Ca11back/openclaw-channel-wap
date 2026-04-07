import { defineChannelPluginEntry } from "openclaw/plugin-sdk/channel-core";
import type { OpenClawPluginApi, PluginRuntime } from "openclaw/plugin-sdk/channel-core";
import { registerWapCli, registerWapCommands, registerWapTools, startWsService, stopWsService, wapPlugin } from "./api.js";
import { setWapRuntime } from "./runtime-api.js";

const entry: {
  id: string;
  name: string;
  description: string;
  configSchema: NonNullable<typeof wapPlugin.configSchema>;
  register: (api: OpenClawPluginApi) => void;
  channelPlugin: typeof wapPlugin;
  setChannelRuntime?: (runtime: PluginRuntime) => void;
} = defineChannelPluginEntry({
  id: "openclaw-channel-wap",
  name: "WeChat (WAP)",
  description: "WeChat channel via WAuxiliary plugin",
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

export default entry;

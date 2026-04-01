import { createPluginRuntimeStore } from "openclaw/plugin-sdk/runtime-store";
import type { PluginRuntime } from "openclaw/plugin-sdk/runtime-store";

const runtimeStore = createPluginRuntimeStore<PluginRuntime>("WAP plugin runtime is not initialized");

export const setWapRuntime = runtimeStore.setRuntime;
export const clearWapRuntime = runtimeStore.clearRuntime;
export const tryGetWapRuntime = runtimeStore.tryGetRuntime;
export const getWapRuntime = runtimeStore.getRuntime;

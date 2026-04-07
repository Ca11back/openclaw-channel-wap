import { defineSetupPluginEntry } from "openclaw/plugin-sdk/channel-core";
import { wapPlugin } from "./src/channel.js";

export default defineSetupPluginEntry(wapPlugin);

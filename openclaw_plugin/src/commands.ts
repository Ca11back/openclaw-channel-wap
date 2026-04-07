import type { OpenClawPluginApi, OpenClawConfig } from "openclaw/plugin-sdk/channel-core";
import { CHANNEL_ID, resolveWapAccount } from "./config.js";
import { buildWapClientDiagnostics } from "./operations.js";

const WAP_DIAGNOSE_COMMAND = "wap-diagnose";
const WAP_DIAGNOSE_DESCRIPTION = "Inspect WAP plugin readiness and connected client capabilities";

function buildWapDoctorText(config: OpenClawConfig, accountId?: string | null): string {
  const resolvedAccount = resolveWapAccount(config, accountId);
  const diagnostics = buildWapClientDiagnostics(resolvedAccount.accountId);
  const rpcMethods = diagnostics.capabilities?.rpc_methods?.join(", ") || "(none advertised)";
  const commandTypes = diagnostics.capabilities?.command_types?.join(", ") || "(none advertised)";

  return [
    `WAP diagnostics for account: ${resolvedAccount.accountId}`,
    `enabled: ${resolvedAccount.enabled}`,
    `configured: ${String(Boolean(resolvedAccount.config.authToken ?? process.env.WAP_AUTH_TOKEN))}`,
    `connectedClients: ${diagnostics.connectedClients}`,
    `protocolVersion: ${diagnostics.capabilities?.protocol_version ?? "(unknown)"}`,
    `rpcMethods: ${rpcMethods}`,
    `commandTypes: ${commandTypes}`,
    `channelId: ${CHANNEL_ID}`,
  ].join("\n");
}

export function registerWapCommands(api: OpenClawPluginApi) {
  api.registerCommand({
    name: "wap_doctor",
    description: WAP_DIAGNOSE_DESCRIPTION,
    acceptsArgs: false,
    requireAuth: true,
    async handler(ctx: { config: OpenClawConfig; accountId?: string | null }) {
      return {
        text: buildWapDoctorText(ctx.config, ctx.accountId),
      };
    },
  });

  api.registerCommand({
    name: "wap",
    description: "WAP plugin commands (doctor, capabilities, help)",
    acceptsArgs: true,
    requireAuth: true,
    async handler(ctx: { config: OpenClawConfig; accountId?: string | null; args?: string }) {
      const subcommand = ctx.args?.trim().split(/\s+/)[0]?.toLowerCase() ?? "help";
      if (subcommand === "doctor" || subcommand === "capabilities" || subcommand === "status") {
        return {
          text: buildWapDoctorText(ctx.config, ctx.accountId),
        };
      }
      return {
        text: [
          "WAP plugin commands:",
          "/wap doctor",
          "/wap capabilities",
          "/wap help",
        ].join("\n"),
      };
    },
  });
}

export function registerWapCli(api: OpenClawPluginApi) {
  api.registerCli(
    (ctx) => {
      ctx.program
        .command(WAP_DIAGNOSE_COMMAND)
        .description(WAP_DIAGNOSE_DESCRIPTION)
        .action(() => {
          // eslint-disable-next-line no-console -- CLI command writes directly to the terminal.
          console.log(buildWapDoctorText(ctx.config));
        });
    },
    {
      commands: [WAP_DIAGNOSE_COMMAND],
      descriptors: [
        {
          name: WAP_DIAGNOSE_COMMAND,
          description: WAP_DIAGNOSE_DESCRIPTION,
          hasSubcommands: false,
        },
      ],
    },
  );
}

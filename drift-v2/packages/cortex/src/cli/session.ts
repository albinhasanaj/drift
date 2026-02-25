/**
 * session — Session management subcommands.
 */

import type { CortexClient } from "../bridge/client.js";

export async function sessionCommand(
  client: CortexClient,
  sub: string,
  positional: string[],
  flags: Record<string, string>,
): Promise<void> {
  switch (sub) {
    case "create": {
      const sessionId = await client.sessionCreate(flags.id);
      console.log(JSON.stringify({ session_id: sessionId }));
      break;
    }
    case "get": {
      const id = positional[0] ?? flags.id;
      if (!id) {
        console.error("  Error: session get requires a session ID.");
        process.exit(1);
      }
      const session = await client.sessionGet(id);
      console.log(JSON.stringify(session, null, 2));
      break;
    }
    case "analytics": {
      const id = positional[0] ?? flags.id;
      if (!id) {
        console.error("  Error: session analytics requires a session ID.");
        process.exit(1);
      }
      const analytics = await client.sessionAnalytics(id);
      console.log(JSON.stringify(analytics, null, 2));
      break;
    }
    case "cleanup": {
      const cleaned = await client.sessionCleanup();
      console.log(JSON.stringify({ sessions_cleaned: cleaned }));
      break;
    }
    default:
      console.error(`  Unknown session subcommand: ${sub}. Valid: create, get, analytics, cleanup`);
      process.exit(1);
  }
}

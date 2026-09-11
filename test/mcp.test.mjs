// Rewritten in Task 14 against the signed interfaces: mcp/server.mjs still
// exposes tools (list_agents, heartbeat) that the broker no longer serves.
// Skipped, not deleted — a silently removed suite is how coverage vanishes.
import test from 'node:test';

test('rewritten for signed identity in Tasks 12 and 14', { skip: true }, () => {});

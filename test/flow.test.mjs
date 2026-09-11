// Rewritten in Task 12 against the signed interfaces: AgentLink no longer
// speaks to the broker with a shared token, so every assertion in the old
// version described a trust model that no longer exists. Skipped, not deleted —
// a silently removed suite is how coverage vanishes.
import test from 'node:test';

test('rewritten for signed identity in Tasks 12 and 14', { skip: true }, () => {});

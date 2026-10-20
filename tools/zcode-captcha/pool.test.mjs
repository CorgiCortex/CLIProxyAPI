import test from "node:test";
import assert from "node:assert/strict";
import { TokenPool } from "./pool.mjs";

function token(id) {
  return { verifyParam: Buffer.from(JSON.stringify({ certifyId: id, sceneId: "scene", securityToken: "test-only" })).toString("base64"), region: "cn" };
}

test("tokens are single use and failures cool down without wall-clock sleeps", async () => {
  let now = 100000;
  const pool = new TokenPool(async () => token("id"), { now: () => now });
  const result = await pool.take("3.16.2");
  assert.equal(result.expires_at, now + 45000);
  await assert.rejects(pool.take("3.16.2"), /duplicate/);
  await assert.rejects(pool.take("3.16.2"), /busy/);
  now += 100000;
  assert.ok((await pool.take("3.16.2")).verify_param);
  assert.equal(pool.pending, 0);
});

test("one solve at a time, bounded admission, and cancelled waiters release slots", async () => {
  let finish;
  let solves = 0;
  const pool = new TokenPool(async () => {
    solves++;
    await new Promise(resolve => { finish = resolve; });
    return token(String(solves));
  }, { maxPending: 2 });
  const one = pool.take("3.16.2");
  await Promise.resolve();
  const abort = new AbortController();
  const two = pool.take("3.16.2", abort.signal);
  await assert.rejects(pool.take("3.16.2"), /busy/);
  abort.abort();
  finish();
  await one;
  await assert.rejects(two, /abort/i);
  assert.equal(solves, 1);
  assert.equal(pool.pending, 0);
});

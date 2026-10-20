// Only short-lived verification parameters enter this pool, never account credentials.
export class TokenPool {
  constructor(solve, { now = Date.now, maxPending = 4, ttl = 45000 } = {}) {
    this.solve = solve;
    this.now = now;
    this.maxPending = maxPending;
    this.ttl = ttl;
    this.pending = 0;
    this.tail = Promise.resolve();
    this.seen = new Map();
    this.retryAt = 0;
  }

  async take(version, signal) {
    if (this.pending >= this.maxPending || this.now() < this.retryAt) {
      throw new Error("verification_worker_busy");
    }
    this.pending++;
    const previous = this.tail;
    let unlock;
    this.tail = new Promise(resolve => { unlock = resolve; });
    try {
      await previous;
      signal?.throwIfAborted();
      if (this.now() < this.retryAt) throw new Error("verification_worker_cooling");
      const token = await this.solve(version, signal);
      const param = token?.verifyParam;
      if (typeof param !== "string" || param.length > 32768) throw new Error("invalid_verification_parameter");
      const parsed = JSON.parse(Buffer.from(param, "base64").toString("utf8"));
      if (typeof parsed.certifyId !== "string" || !parsed.certifyId ||
          typeof parsed.sceneId !== "string" || !parsed.sceneId ||
          typeof parsed.securityToken !== "string" || !parsed.securityToken) {
        throw new Error("invalid_verification_parameter");
      }
      const now = this.now();
      for (const [id, expiry] of this.seen) if (expiry <= now) this.seen.delete(id);
      if (this.seen.has(parsed.certifyId)) throw new Error("duplicate_verification_parameter");
      this.seen.set(parsed.certifyId, now + this.ttl * 2);
      return { verify_param: param, region: token.region, expires_at: now + this.ttl };
    } catch (error) {
      if (!signal?.aborted) this.retryAt = this.now() + 15000;
      throw error;
    } finally {
      this.pending--;
      unlock();
    }
  }
}

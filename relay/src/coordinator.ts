export interface DurableStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  list<T>(options?: { limit?: number; startAfter?: string }): Promise<Map<string, T>>;
  getAlarm(): Promise<number | null>;
  setAlarm(time: number): Promise<void>;
  transaction<T>(closure: (transaction: DurableStorage) => Promise<T>): Promise<T>;
}
export interface DurableState { storage: DurableStorage }
type Expiring<T> = { value: T; expires: number };

/** Strongly serialized OAuth and abuse-control state. One global instance is used. */
export class RelayCoordinator {
  constructor(private readonly state: DurableState) {}
  private async scheduleCleanup(storage: DurableStorage) {
    const next = Date.now() + 60_000;
    const alarm = await storage.getAlarm();
    if (alarm === null || alarm > next) await storage.setAlarm(next);
  }
  async fetch(request: Request): Promise<Response> {
    const { op, key, value, ttl, maximum, bindings } = await request.json() as Record<string, any>;
    const storage = this.state.storage;
    if (op === "rate") {
      const rateKey = `rate:${key}:${Math.floor(Date.now() / 60_000)}`;
      const count = await storage.transaction(async transaction => {
        const record = await transaction.get<Expiring<number>>(rateKey);
        const next = (record?.expires || 0) > Date.now() ? record!.value + 1 : 1;
        await transaction.put(rateKey, { value: next, expires: (Math.floor(Date.now() / 60_000) + 1) * 60_000 });
        return next;
      });
      await this.scheduleCleanup(storage);
      return Response.json({ allowed: count <= Number(maximum) });
    }
    if (op === "registration") {
      const window = Math.floor(Date.now() / 86_400_000);
      const registrationKey = `registration:${window}`;
      const allowed = await storage.transaction(async transaction => {
        const record = await transaction.get<Expiring<number>>(registrationKey);
        const count = (record?.expires || 0) > Date.now() ? record!.value : 0;
        if (count >= Number(maximum)) return false;
        await transaction.put(registrationKey, { value: count + 1, expires: (window + 1) * 86_400_000 });
        return true;
      });
      await this.scheduleCleanup(storage);
      return Response.json({ allowed });
    }
    if (op === "put") {
      await storage.put(String(key), { value, expires: Date.now() + Number(ttl) } satisfies Expiring<unknown>);
      await this.scheduleCleanup(storage);
      return Response.json({ ok: true });
    }
    if (op === "take") {
      const taken = await storage.transaction(async transaction => {
        const record = await transaction.get<Expiring<any>>(String(key));
        if (!record || record.expires <= Date.now() || (bindings && Object.entries(bindings).some(([name, expected]) => record.value?.[name] !== expected))) return null;
        await transaction.delete(String(key));
        return record.value;
      });
      return Response.json({ value: taken });
    }
    const record = await storage.get<Expiring<any>>(String(key));
    if (!record || record.expires <= Date.now()) {
      if (record) await storage.delete(String(key));
      return Response.json({ value: null });
    }
    if (op === "get") return Response.json({ value: record.value });
    return Response.json({ error: "invalid_operation" }, { status: 400 });
  }

  async alarm(): Promise<void> {
    const storage = this.state.storage;
    const cursorRecord = await storage.get<Expiring<string>>("cleanup-cursor");
    const cursor = (cursorRecord?.expires || 0) > Date.now() ? cursorRecord!.value : "";
    const records = await storage.list<Expiring<unknown>>({ limit: 128, ...(cursor ? { startAfter: cursor } : {}) });
    let last = "";
    for (const [key, record] of records) {
      last = key;
      if (key !== "cleanup-cursor" && record.expires <= Date.now()) await storage.delete(key);
    }
    if (records.size === 128) {
      await storage.put("cleanup-cursor", { value: last, expires: Date.now() + 300_000 });
      await storage.setAlarm(Date.now() + 1);
    } else {
      await storage.delete("cleanup-cursor");
      if ([...records.keys()].some(key => key !== "cleanup-cursor")) await storage.setAlarm(Date.now() + 60_000);
    }
  }
}

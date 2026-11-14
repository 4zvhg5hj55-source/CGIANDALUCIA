import { DurableObject } from 'cloudflare:workers';
import { createCore } from './core.js';

const DAY = 864e5;

// Todo el backend vive en UN Durable Object (con SQLite): los datos son persistentes y consistentes.
export class CGI extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.env = env;
    this.core = createCore(ctx.storage.sql, env);
    // Copia automática diaria: una alarma del propio Durable Object (no necesita configuración).
    // Si ya hay una programada no hace nada; la primera salta una hora después del primer arranque.
    ctx.blockConcurrencyWhile(async () => {
      if ((await ctx.storage.getAlarm()) == null) await ctx.storage.setAlarm(Date.now() + 3600e3);
    });
  }
  async fetch(request) {
    return this.core.handle(request);
  }
  async alarm() {
    try {
      this.core.autoSnapshot(); // punto de restauración interno (solo si ha habido actividad desde el último)
    } catch (e) {
      console.error('Punto de restauración automático fallido:', e && e.stack || e);
    }
    try {
      this.core.weeklyInactivity(); // aviso semanal de inactividad (<3 h) al Discord de los superiores, si hay webhook
    } catch (e) {
      console.error('Aviso de inactividad fallido:', e && e.stack || e);
    }
    try {
      if (this.env.BACKUPS) await this.offsite(); // copia externa en R2 (opcional)
    } finally {
      await this.ctx.storage.setAlarm(Date.now() + DAY); // pase lo que pase, se reprograma
    }
  }
  // Copia completa a R2 una vez al día; se conservan las 30 más recientes. Solo si has activado el binding BACKUPS (ver wrangler.jsonc).
  async offsite() {
    const key = `cgi-backup-${new Date().toISOString().slice(0, 10)}.json`;
    try {
      const body = this.core.backupJson();
      await this.env.BACKUPS.put(key, body, { httpMetadata: { contentType: 'application/json' } });
      const old = (await this.env.BACKUPS.list({ prefix: 'cgi-backup-' })).objects.map((o) => o.key).sort().reverse().slice(30);
      if (old.length) await this.env.BACKUPS.delete(old);
      this.core.noteOffsite({ ts: new Date().toISOString(), key, bytes: body.length, ok: true });
    } catch (e) {
      console.error('Copia externa a R2 fallida:', e && e.stack || e);
      this.core.noteOffsite({ ts: new Date().toISOString(), key, ok: false, err: String((e && e.message) || e).slice(0, 200) });
    }
  }
}

// Los archivos de /public los sirve Cloudflare directamente; aquí solo llegan las peticiones /api/*
export default {
  async fetch(request, env) {
    const stub = env.CGI.get(env.CGI.idFromName('principal'), { locationHint: 'weur' });
    return stub.fetch(request);
  },
};

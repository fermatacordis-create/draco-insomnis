/**
 * Koa, and Strapi (whose middlewares are Koa middlewares).
 *
 *   import Koa from 'koa';
 *   import { draco } from 'draco-insomnis/koa';
 *   app.use(draco({ waf: 'block' }));
 *
 * Strapi 4/5: src/middlewares/draco.js
 *   import { strapi } from 'draco-insomnis/koa';
 *   export default strapi;
 * and add { name: 'global::draco', config: { waf: 'block' } } near the top of config/middlewares.js.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Gatekeeper, type DracoOptions } from './core/gatekeeper.ts';
import { fromNode, nodeResolver, reply, secure } from './node.ts';

export interface KoaContext {
  req: IncomingMessage;
  res: ServerResponse;
  originalUrl?: string;
  url: string;
  query?: unknown;
  request: { body?: unknown };
  status: number;
  body: unknown;
  set(field: string, value: string): void;
}

export type KoaMiddleware = ((ctx: KoaContext, next: () => Promise<unknown>) => Promise<void>) & { gate: Gatekeeper };

export function draco(options: DracoOptions = {}): KoaMiddleware {
  const gate = new Gatekeeper({ resolver: nodeResolver, ...options });
  const middleware = async (ctx: KoaContext, next: () => Promise<unknown>): Promise<void> => {
    let answer = null;
    try {
      answer = await gate.decide(fromNode(ctx.req, ctx.originalUrl ?? ctx.url, ctx.query, ctx.request.body));
    } catch {
      // Draco itself failing never takes the site with it.
    }
    if (answer !== null) {
      const out = reply(gate, answer);
      ctx.status = out.status;
      for (const [k, v] of Object.entries(out.headers)) ctx.set(k, v);
      ctx.body = out.body;
      return;
    }
    secure(gate, ctx.req, ctx.res);
    await next();
  };
  return Object.assign(middleware, { gate });
}

/** Strapi's middleware factory: (config, { strapi }) => Koa middleware. */
export const strapi = (config: DracoOptions = {}): KoaMiddleware => draco(config);

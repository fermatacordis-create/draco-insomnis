/**
 * Express (and anything with the same middleware shape: Connect, Directus, plain node:http).
 *
 *   import express from 'express';
 *   import { draco } from 'draco-insomnis/express';
 *   const app = express();
 *   app.use(express.urlencoded({ extended: false }), express.json()); // optional: lets the firewall read forms
 *   app.use(draco({ waf: 'block' }));
 *
 * Directus (a hook extension):
 *   import { directus } from 'draco-insomnis/express';
 *   export default directus({ waf: 'block' });
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Gatekeeper, type DracoOptions } from './core/gatekeeper.ts';
import { fromNode, nodeResolver, reply, secure, send } from './node.ts';

type Req = IncomingMessage & { originalUrl?: string; query?: unknown; body?: unknown };
type Next = (err?: unknown) => void;

export type DracoMiddleware = ((req: Req, res: ServerResponse, next: Next) => void) & { gate: Gatekeeper };

export function draco(options: DracoOptions = {}): DracoMiddleware {
  const gate = new Gatekeeper({ resolver: nodeResolver, ...options });
  const middleware = (req: Req, res: ServerResponse, next: Next): void => {
    const r = fromNode(req, req.originalUrl ?? req.url ?? '/', req.query, req.body);
    gate.decide(r).then(
      (answer) => {
        if (answer !== null) {
          send(res, reply(gate, answer));
          return;
        }
        secure(gate, req, res);
        next();
      },
      // Draco itself failing (a store down…) never takes the site with it.
      () => next(),
    );
  };
  return Object.assign(middleware, { gate });
}

/** A Directus hook extension: Draco runs before every Directus route. */
export function directus(options: DracoOptions = {}) {
  return ({ init }: { init: (event: string, fn: (meta: { app: { use: (m: DracoMiddleware) => void } }) => void) => void }): void => {
    init('middlewares.before', ({ app }) => app.use(draco(options)));
  };
}

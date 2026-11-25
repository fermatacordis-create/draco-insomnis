/** Draco Insomnis for JavaScript: the engine, with no framework. Adapters: ./express, ./koa, ./worker. */
export { Gatekeeper, SENSITIVE, TEXTS, list, page, render, type Answer, type DracoOptions, type Mode } from './core/gatekeeper.ts';
export { open, seal, sign, type ReviewRequest } from './core/review.ts';
export { CrowdSec, crowdsecLine, seconds as crowdsecSeconds, type CrowdSecOptions, type SyncResult } from './core/crowdsec.ts';
export { CLOUDFLARE, LOCAL_PROXIES, contains, inNet, isIP, network, parse } from './core/net.ts';
export { clientIp, urlDecode, type DracoRequest, type ProxyMode } from './core/request.ts';
export { Blocks, MemoryStore, validNet, type BlockEntry, type DracoEvent, type Store } from './core/store.ts';
export { flatten, inspect, type WafInput, type WafRule } from './core/waf.ts';
export type { Resolver } from './core/crawler.ts';
export const VERSION = '0.1.38';

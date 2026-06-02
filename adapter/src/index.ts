#!/usr/bin/env node
// Entrypoint: load config, build app, start HTTP listener.

import { loadConfig } from './config.js';
import { buildApp } from './http.js';

function main(): void {
  let cfg;
  try {
    cfg = loadConfig();
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error(`[adapter] config error: ${(e as Error).message}`);
    process.exit(1);
  }

  const app = buildApp(cfg);
  const server = app.listen(cfg.port, () => {
    // eslint-disable-next-line no-console
    console.error(
      `[adapter] listening on :${cfg.port}\n` +
        `  publicBaseUrl=${cfg.publicBaseUrl}\n` +
        `  companyDomain=${cfg.companyDomain}\n` +
        `  scopes=${cfg.oauthScopes}\n` +
        `  bearerTtl=${cfg.bearerTtlSeconds}s refreshSkew=${cfg.refreshSkewSeconds}s`,
    );
  });

  const shutdown = (sig: string) => {
    // eslint-disable-next-line no-console
    console.error(`[adapter] received ${sig}, closing...`);
    server.close(() => process.exit(0));
    // Hard exit if it hangs
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main();

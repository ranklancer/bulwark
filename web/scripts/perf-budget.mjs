#!/usr/bin/env node
//
// Bundle-size budget gate. Walks the Vite build output, gzips each
// file in memory, and fails if any of the configured budgets are
// exceeded:
//
//   - Any single chunk > BULWARK_PERF_PER_CHUNK_GZ_KB (default 200)
//   - Entry chunk + vendor chunk combined > BULWARK_PERF_ENTRY_GZ_KB (default 350)
//   - Total CSS > BULWARK_PERF_CSS_GZ_KB (default 40)
//
// Runs after `npm run build`. The CI workflow chains them in order;
// `npm run perf:check` is the local-dev alias.

import { readdirSync, readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST = resolve(__dirname, "../../internal/api/ui-react/dist/assets");

const PER_CHUNK_KB = Number(process.env.BULWARK_PERF_PER_CHUNK_GZ_KB ?? 200);
const ENTRY_KB = Number(process.env.BULWARK_PERF_ENTRY_GZ_KB ?? 350);
const CSS_KB = Number(process.env.BULWARK_PERF_CSS_GZ_KB ?? 40);

let files;
try {
  files = readdirSync(DIST).map((name) => {
    const path = resolve(DIST, name);
    const raw = readFileSync(path);
    const gz = gzipSync(raw, { level: 9 }).length;
    return { name, raw: raw.length, gz };
  });
} catch (err) {
  if (err.code === "ENOENT") {
    console.error(`perf-budget: ${DIST} does not exist`);
    console.error("perf-budget: run `npm run build` first.");
    process.exit(1);
  }
  throw err;
}

if (files.length === 0) {
  console.error(`perf-budget: no files in ${DIST}`);
  console.error("perf-budget: run `npm run build` first.");
  process.exit(1);
}

const violations = [];
const perChunkLimit = PER_CHUNK_KB * 1024;
for (const f of files) {
  if (f.gz > perChunkLimit) {
    violations.push(
      `${f.name}: ${(f.gz / 1024).toFixed(1)} KB gzipped > ${PER_CHUNK_KB} KB limit`,
    );
  }
}

const entry = files.find((f) => /^index-.*\.js$/.test(f.name));
const vendor = files.find((f) => /^vendor-.*\.js$/.test(f.name));
const entryGz = (entry?.gz ?? 0) + (vendor?.gz ?? 0);
const entryLimit = ENTRY_KB * 1024;
if (entryGz > entryLimit) {
  violations.push(
    `entry+vendor: ${(entryGz / 1024).toFixed(1)} KB gzipped > ${ENTRY_KB} KB limit`,
  );
}

const cssGz = files
  .filter((f) => f.name.endsWith(".css"))
  .reduce((sum, f) => sum + f.gz, 0);
const cssLimit = CSS_KB * 1024;
if (cssGz > cssLimit) {
  violations.push(
    `total CSS: ${(cssGz / 1024).toFixed(1)} KB gzipped > ${CSS_KB} KB limit`,
  );
}

console.log("perf-budget: chunk sizes (gzip):");
for (const f of [...files].sort((a, b) => b.gz - a.gz)) {
  const gzStr = `${(f.gz / 1024).toFixed(2)} KB`;
  console.log(`  ${f.name.padEnd(42)} ${gzStr.padStart(10)}`);
}
console.log("");
console.log(`perf-budget: entry+vendor = ${(entryGz / 1024).toFixed(2)} KB (limit ${ENTRY_KB})`);
console.log(`perf-budget: total CSS    = ${(cssGz / 1024).toFixed(2)} KB (limit ${CSS_KB})`);
console.log("");

if (violations.length > 0) {
  console.error("perf-budget: VIOLATIONS:");
  for (const v of violations) console.error(`  - ${v}`);
  process.exit(1);
}

console.log("perf-budget: PASS");

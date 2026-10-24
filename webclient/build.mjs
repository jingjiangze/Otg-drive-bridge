// Builds webclient/dist/index.html — the deployable single file.
//
// Why single-file: the page's visitors are mainland-China browsers and every
// extra request is an offshore round trip (CF edge ~1.4s, jsDelivr ~0.8s
// measured 2026-10-24). A resource-mirror chain also risks serial TCP-timeout
// blackholing when a mirror is unreachable. dist/index.html carries
// everything inline: one request, and its _headers give it a 1-day browser
// cache with stale-while-revalidate, so repeat opens are instant.
//
// Usage: node build.mjs [git-sha]
import fs from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const read = f => fs.readFileSync(path.join(here, f), 'utf8');

const sha = process.argv[2] || new Date().toISOString().slice(0, 10);
let html = read('index.html');
const css = read('style.css');
const js = read('app.js');

// A literal "</script" inside the inlined JS/CSS would close the tag early;
// fail the build instead of shipping a broken page.
if (/<\/script/i.test(js)) throw new Error('app.js contains </script');
if (/<\/style/i.test(css)) throw new Error('style.css contains </style');

if (!html.includes('<link rel="stylesheet" href="style.css">')) {
  throw new Error('index.html: stylesheet link placeholder missing');
}
html = html.replace('<link rel="stylesheet" href="style.css">', `<style>\n${css}\n</style>`);

if (!html.includes('<script src="app.js"></script>')) {
  throw new Error('index.html: script placeholder missing');
}
html = html.replace('<script src="app.js"></script>', `<script>\n${js}\n</script>`);

const entries = [
  '备用入口：<a href="https://otg-drive-bridge.pages.dev/">otg-drive-bridge.pages.dev</a>',
  `build <code>${sha}</code>`,
];
html = html.replace('<!-- ENTRIES-BELOW -->', `<br>${entries.join(' · ')}`);

const outDir = path.join(here, 'dist');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'index.html'), html);
fs.writeFileSync(path.join(outDir, '_headers'), read('dist/_headers'));
console.log(`dist/index.html ${(Buffer.byteLength(html) / 1024).toFixed(1)} KB (build ${sha})`);

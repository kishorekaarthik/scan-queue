// Screenshots the live dashboard once per second, from the moment <goFile>
// appears until <stopFile> appears. The browser is launched and the page loaded
// beforehand, so the first frame is taken the instant the go signal arrives.
// Dev tool only: Playwright is resolved from the tool directory via NODE_PATH,
// it is NOT a project dependency (see make-dashboard-gif.sh).
//   node capture-dashboard.cjs <url> <outDir> <goFile> <stopFile> <maxFrames>
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const [url, outDir, goFile, stopFile, maxFrames = '400'] = process.argv.slice(2);
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1000, height: 680 }, deviceScaleFactor: 1, colorScheme: 'light' });
  for (;;) {                                   // the API may still be starting
    try { await page.goto(url, { waitUntil: 'networkidle', timeout: 5000 }); break; } catch { await sleep(1000); }
  }
  console.log('page loaded, waiting for go signal');
  while (!fs.existsSync(goFile)) await sleep(100);
  // Reload: the demo may have recreated the API container (new image) since the
  // first load, and the page must run the JavaScript of the current build.
  await page.reload({ waitUntil: 'networkidle' });
  await sleep(1200);                           // one dashboard refresh after the reset
  let n = 0;
  const start = Date.now();
  while (n < Number(maxFrames) && !fs.existsSync(stopFile)) {
    const wait = start + n * 1000 - Date.now();
    if (wait > 0) await sleep(wait);
    n++;
    await page.screenshot({ path: path.join(outDir, `frame-${String(n).padStart(4, '0')}.png`) });
  }
  await browser.close();
  console.log(`captured ${n} frames`);
})().catch(e => { console.error(e); process.exit(1); });

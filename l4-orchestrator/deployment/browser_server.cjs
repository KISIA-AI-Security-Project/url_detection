// The caller binds this server to a dedicated guest and host-loopback port.
const { chromium } = require(process.env.L4_PLAYWRIGHT_PACKAGE);
(async () => {
  const server = await chromium.launchServer({
    headless: true,
    chromiumSandbox: true,
    host: '0.0.0.0',
    port: 3000,
    wsPath: process.env.L4_WS_PATH,
  });
  console.log('L4_BROWSER_READY ' + server.wsEndpoint());
})().catch(error => {
  console.error('L4_BROWSER_START_FAILED ' + error.message);
  process.exit(1);
});

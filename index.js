const pm2 = require('pm2');
const http = require('http');

const appName = 'api-server';
const scriptPath = './api.js';
const HEALTHCHECK_INTERVAL = 15000; // tiap 15 detik cek
const HEALTH_TIMEOUT = 30000; // timeout 30 detik

function forceRestart() {
  pm2.delete(appName, () => {
    pm2.start({
      name: appName,
      script: scriptPath,
      autorestart: true,
      restart_delay: 2000,
      env: {
        NODE_ENV: 'production',
        PORT: 2090
      }
    }, (err) => {
      if (err) console.error('[FORCE RESTART] Gagal start ulang:', err.message);
      else console.log('[FORCE RESTART] Berhasil restart ulang secara paksa');
    });
  });
}

function startHealthWatcher() {
  setInterval(() => {
    const req = http.get('http://localhost:2090/api/health', res => {
      if (res.statusCode !== 200) {
        console.warn('[HEALTH CHECK] Status bukan 200, restart...');
        pm2.restart(appName);
      }
    });

    req.setTimeout(HEALTH_TIMEOUT, () => {
      console.warn('[HEALTH CHECK] Timeout, restart paksa...');
      req.destroy();
      forceRestart();
    });

    req.on('error', () => {
      console.warn('[HEALTH CHECK] Tidak bisa konek ke /api/health, restart paksa...');
      forceRestart();
    });
  }, HEALTHCHECK_INTERVAL);
}

pm2.connect(function (err) {
  if (err) {
    console.error('Gagal konek ke PM2:', err);
    process.exit(2);
  }

  pm2.list((err, list) => {
    if (err) {
      console.error('Gagal ambil list PM2:', err);
      pm2.disconnect();
      return;
    }

    const already = list.find(proc => proc.name === appName);

    const startApp = () => {
      pm2.start({
        name: appName,
        script: scriptPath,
        autorestart: true,
        restart_delay: 2000,
        env: {
          NODE_ENV: 'production',
          PORT: 2090
        }
      }, (err) => {
        if (err) {
          console.error('Gagal start:', err);
        } else {
          console.log(`[OK] ${appName} dijalankan via PM2`);
          startHealthWatcher();
        }
        pm2.disconnect();
      });
    };

    if (already) {
      console.log(`[INFO] ${appName} sudah berjalan`);
      startHealthWatcher();
      pm2.disconnect();
    } else {
      startApp();
    }
  });
});

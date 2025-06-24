const pm2 = require('pm2');
const http = require('http');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');

const appName = 'api-server';
const scriptPath = './api.js';
const HEALTHCHECK_INTERVAL = 30000;
const HEALTH_TIMEOUT = 60000;
const UPDATE_INTERVAL = 5 * 60 * 1000;
const REMOTE_SCRIPT_URL = 'https://botapi.ihsan83636.workers.dev/api.js'; // Worker URL kamu

// Hashing util
function getHash(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

// Force restart API
function forceRestart() {
  pm2.delete(appName, () => {
    pm2.start({
      name: appName,
      script: scriptPath,
      autorestart: true,
      restart_delay: 5000,
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

// Health checker
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

// Auto-update checker
function checkForUpdate() {
  https.get(REMOTE_SCRIPT_URL, res => {
    if (res.statusCode !== 200) {
      console.warn('[UPDATE] Gagal ambil update:', res.statusCode);
      return;
    }

    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
      try {
        const remoteHash = getHash(data);
        const localData = fs.readFileSync(scriptPath, 'utf-8');
        const localHash = getHash(localData);

        if (remoteHash !== localHash) {
          console.log('[UPDATE] Versi baru ditemukan. Update dimulai...');
          try {
            if (fs.existsSync(scriptPath + '.bak')) {
              fs.unlinkSync(scriptPath + '.bak');
            }
            fs.copyFileSync(scriptPath, scriptPath + '.bak');
          } catch (err) {
            console.error('[UPDATE] Gagal backup file lama:', err.message);
            return;
          }

          try {
            fs.writeFileSync(scriptPath, data);
            pm2.restart(appName, err => {
              if (err) console.error('[UPDATE] Gagal restart setelah update:', err.message);
              else console.log('[UPDATE] Update dan restart berhasil!');
            });
          } catch (err) {
            console.error('[UPDATE] Gagal menulis file update:', err.message);
          }
        } else {
          console.log('[UPDATE] Tidak ada perubahan.');
        }
      } catch (e) {
        console.error('[UPDATE] Error saat proses update:', e.message);
      }
    });
  }).on('error', err => {
    console.error('[UPDATE] Gagal fetch update:', err.message);
  });
}

// PM2 init
pm2.connect(err => {
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
        restart_delay: 5000,
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
          setInterval(checkForUpdate, UPDATE_INTERVAL);
          checkForUpdate(); // pertama kali langsung cek
        }
        pm2.disconnect();
      });
    };

    if (already) {
      console.log(`[INFO] ${appName} sudah berjalan`);
      startHealthWatcher();
      setInterval(checkForUpdate, UPDATE_INTERVAL);
      checkForUpdate(); // pertama kali langsung cek
      pm2.disconnect();
    } else {
      startApp();
    }
  });
});

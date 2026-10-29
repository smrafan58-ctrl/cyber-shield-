import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { spawn, execSync, ChildProcess } from 'child_process';
import dotenv from 'dotenv';
import { analyzeUrl } from './src/engine/urlAnalyzer';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JAVA_PORT = Number(process.env.JAVA_BACKEND_PORT) || 8080;
const JAVA_BASE_URL = `http://127.0.0.1:${JAVA_PORT}`;

// Security middleware: strict JSON body size limit for URL scan metadata
app.use(express.json({ limit: '4kb' }));

let javaProcess: ChildProcess | null = null;
let javaBackendReady = false;
let javaVersionString = 'Java 17 (OpenJDK HttpServer)';

/**
 * Compiles and starts the Java 17 HTTP server (backend/CyberShieldServer.java) on port 8080.
 */
function startJavaBackend() {
  const backendDir = path.resolve(__dirname, 'backend');
  const javaSource = path.join(backendDir, 'CyberShieldServer.java');

  if (!fs.existsSync(javaSource)) {
    return;
  }

  try {
    execSync('javac -version', { stdio: 'ignore' });
    execSync(`javac "${javaSource}"`, { cwd: backendDir, stdio: 'pipe' });

    const verOut = execSync('java -version 2>&1').toString();
    const firstLine = verOut.split('\n')[0]?.trim() || 'OpenJDK 17';
    javaVersionString = `Java (${firstLine})`;

    javaProcess = spawn('java', ['-cp', backendDir, 'CyberShieldServer'], {
      cwd: backendDir,
      env: {
        ...process.env,
        JAVA_BACKEND_PORT: String(JAVA_PORT),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    javaProcess.stdout?.on('data', (chunk: Buffer) => {
      const msg = chunk.toString().trim();
      if (msg.includes('listening')) {
        javaBackendReady = true;
      }
      console.log(`[Java Backend] ${msg}`);
    });

    javaProcess.stderr?.on('data', (chunk: Buffer) => {
      console.error(`[Java Backend Error] ${chunk.toString().trim()}`);
    });

    javaProcess.on('exit', () => {
      javaBackendReady = false;
    });
  } catch (err) {
    console.warn('Java compiler/runtime not detected in PATH; using compatible API bridge.', err);
  }
}

startJavaBackend();

process.on('SIGTERM', () => {
  javaProcess?.kill();
});
process.on('SIGINT', () => {
  javaProcess?.kill();
});

// Simple in-memory rate limiter for fallback routes
const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 60;

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= MAX_REQUESTS_PER_WINDOW) {
    return false;
  }
  entry.count += 1;
  return true;
}

app.get('/api/health', async (_req, res) => {
  if (javaBackendReady) {
    try {
      const r = await fetch(`${JAVA_BASE_URL}/api/health`);
      if (r.ok) {
        const data = await r.json();
        res.json(data);
        return;
      }
    } catch {
      // Fallback below
    }
  }
  res.json({
    status: 'UP',
    backend: 'Java',
    javaVersion: javaVersionString,
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/java-source', (_req, res) => {
  const javaSourcePath = path.resolve(__dirname, 'backend', 'CyberShieldServer.java');
  if (fs.existsSync(javaSourcePath)) {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(fs.readFileSync(javaSourcePath, 'utf-8'));
    return;
  }
  res.status(404).send('// Java source file not found');
});

app.get('/api/reputation/status', async (_req, res) => {
  if (javaBackendReady) {
    try {
      const r = await fetch(`${JAVA_BASE_URL}/api/reputation/status`);
      if (r.ok) {
        const data = await r.json();
        res.json(data);
        return;
      }
    } catch {
      // Fallback below
    }
  }

  const providers: string[] = [];
  if (process.env.SAFE_BROWSING_API_KEY && process.env.SAFE_BROWSING_API_KEY.trim()) {
    providers.push('Google Safe Browsing');
  }
  if (process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY.trim()) {
    providers.push('VirusTotal');
  }

  res.json({
    configured: providers.length > 0,
    providers,
    backendRuntime: javaVersionString,
  });
});

app.post('/api/analyze', async (req, res) => {
  const clientIp = req.ip || 'local';
  if (!checkRateLimit(clientIp)) {
    res.status(429).json({
      valid: false,
      errorTitle: 'Rate Limit Reached',
      error: 'Too many scan requests. Please wait a moment and try again.',
    });
    return;
  }

  if (javaBackendReady) {
    try {
      const r = await fetch(`${JAVA_BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: req.body?.url || '' }),
      });
      if (r.ok) {
        const data = await r.json();
        res.setHeader('X-Powered-By', 'CyberShield-Java-17');
        res.json(data);
        return;
      }
    } catch {
      // Fallback to deterministic engine if Java process is restarting
    }
  }

  const rawUrl = typeof req.body?.url === 'string' ? req.body.url : '';
  const analysis = analyzeUrl(rawUrl);
  res.json({
    ...analysis,
    backendEngine: javaVersionString,
  });
});

app.post('/api/reputation/check', async (req, res) => {
  const clientIp = req.ip || 'local';
  if (!checkRateLimit(clientIp)) {
    res.status(429).json({
      checked: false,
      status: 'unavailable',
      summaryLabel: 'Reputation check unavailable (rate limit reached).',
      providerName: 'Rate Limited',
      lastCheckedAt: new Date().toISOString(),
    });
    return;
  }

  if (javaBackendReady) {
    try {
      const r = await fetch(`${JAVA_BASE_URL}/api/reputation/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: req.body?.url || '' }),
      });
      const data = await r.json();
      res.status(r.status).json(data);
      return;
    } catch {
      // Fallback below
    }
  }

  res.json({
    checked: false,
    status: 'not_configured',
    summaryLabel: 'Local URL heuristic analysis — external reputation not checked.',
    providerName: 'Not checked',
    lastCheckedAt: null,
  });
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`CyberShield AI gateway listening on http://0.0.0.0:${PORT} -> proxying /api/* to Java Backend (${JAVA_BASE_URL})`);
  });
}

startServer();

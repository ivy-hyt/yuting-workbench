/**
 * 雨婷工作台后端服务
 * - 托管 dist/ 静态前端（PWA 页面）
 * - /api/health/* 处理华为运动健康 OAuth 授权 + 数据同步
 *
 * 设计：纯 Node 零依赖。OAuth 的 client_secret 只存在于服务端，前端不触碰。
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const ROOT = path.join(__dirname, '..');
const DIST = path.join(ROOT, 'dist');
const PORT = process.env.PORT || 3000;

// ---------- 读取 .env（仅本地测试用，部署时由环境变量注入） ----------
function loadEnv() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  const txt = fs.readFileSync(envPath, 'utf-8');
  txt.split('\n').forEach(line => {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
}
loadEnv();

const CFG = {
  clientId: process.env.HW_CLIENT_ID || '',
  clientSecret: process.env.HW_CLIENT_SECRET || '',
  // 回调地址默认按请求域名自动生成（见 /api/health/login），此处可覆盖
  redirectUri: process.env.HW_REDIRECT_URI || '',
  // 前端来源：华为授权完成后跳回的地址 + 允许跨域请求的来源
  frontendOrigin: process.env.HW_FRONTEND_ORIGIN || '',
  corsOrigin: process.env.HW_CORS_ORIGIN || (process.env.HW_FRONTEND_ORIGIN || ''),
  // AI 配置：密钥仅在后端环境变量，前端不再触碰
  // 默认走智谱 GLM-4-Flash（永久免费）；deepseek/doubao 保留为备选
  aiProvider: process.env.AI_PROVIDER || 'zhipu',
  zhipuKey: process.env.ZHIPU_API_KEY || '',
  zhipuModel: process.env.ZHIPU_MODEL || 'glm-4-flash',
  deepseekKey: process.env.DEEPSEEK_API_KEY || '',
  doubaoKey: process.env.DOUBAO_API_KEY || '',
  doubaoEndpoint: process.env.DOUBAO_ENDPOINT || '',
};

// 允许跨域的来源（Web 前端 + iOS Capacitor 壳）
// 未显式配置前端域名时，动态放行任意网页来源（适配 CloudStudio 等动态域名部署）
const EXPLICIT_ORIGINS = [CFG.frontendOrigin, CFG.corsOrigin, 'capacitor://localhost', 'ionic://localhost'].filter(Boolean);
const ALLOWED_ORIGINS = new Set(EXPLICIT_ORIGINS);
const CORS_OPEN_MODE = EXPLICIT_ORIGINS.length === 0;

// 按请求域名推导回调地址（部署到任何平台都无需手工改）
function resolveRedirectUri(req) {
  if (CFG.redirectUri) return CFG.redirectUri;
  const proto = (req.headers['x-forwarded-proto'] || 'http');
  const host = req.headers.host;
  return `${proto}://${host}/api/health/callback`;
}

// 需要的华为数据权限范围
const SCOPE = [
  'openid',
  'https://www.huawei.com/healthkit/step.read',
  'https://www.huawei.com/healthkit/heightweight.read',
  'https://www.huawei.com/healthkit/calories.read',
  'https://www.huawei.com/healthkit/heartrate.read',
  'https://www.huawei.com/healthkit/sleep.read',
].join(' ');

const AUTH_BASE = 'https://oauth-login.cloud.huawei.com/oauth2/v3/authorize';
const TOKEN_URL = 'https://oauth-login.cloud.huawei.com/oauth2/v3/token';
const HEALTH_API = 'https://health-api.cloud.huawei.com';

// ---------- 会话 / Token 存储（内存，单进程） ----------
// sid -> { accessToken, refreshToken, expiresAt, openId }
const sessions = new Map();

function genSid() {
  return crypto.randomBytes(16).toString('hex');
}

function getCookie(req, name) {
  const sc = req.headers.cookie || '';
  const m = sc.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? m[1] : null;
}

function setCookie(res, name, value, maxAge = 2592000) {
  // SameSite=None + Secure：允许前端(CloudStudio)跨站携带会话 Cookie 访问后端(Render)
  res.setHeader('Set-Cookie', `${name}=${value}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=None; Secure`);
}

// CORS：允许 Web 前端与 iOS Capacitor 壳，并支持携带凭据
function applyCors(res, req) {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.has(origin) || CORS_OPEN_MODE) {
    // 未显式配置来源时，回退为请求来源本身（支持任意网页前端）
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  }
}

// ---------- 华为 OAuth 辅助 ----------
async function exchangeToken(code, redirectUri) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: CFG.clientId,
    client_secret: CFG.clientSecret,
    redirect_uri: redirectUri,
  });
  const resp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error('token exchange failed: ' + text);
  return JSON.parse(text);
}

async function refreshAccessToken(refreshToken) {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: CFG.clientId,
    client_secret: CFG.clientSecret,
  });
  const resp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const text = await resp.text();
  if (!resp.ok) throw new Error('token refresh failed: ' + text);
  return JSON.parse(text);
}

// 确保拿到有效的 access_token（过期则用 refresh_token 刷新）
async function ensureAccessToken(sess) {
  if (sess.accessToken && sess.expiresAt && Date.now() < sess.expiresAt - 60000) {
    return sess.accessToken;
  }
  if (sess.refreshToken) {
    const t = await refreshAccessToken(sess.refreshToken);
    sess.accessToken = t.access_token;
    sess.expiresAt = Date.now() + (t.expires_in || 3600) * 1000;
    if (t.refresh_token) sess.refreshToken = t.refresh_token;
    return sess.accessToken;
  }
  throw new Error('no valid token');
}

async function callHealthApi(pathname, method, accessToken, bodyObj) {
  const headers = {
    'Content-Type': 'application/json; charset=UTF-8',
    'Authorization': 'Bearer ' + accessToken,
    'x-client-id': CFG.clientId,
    'x-version': '1.0.0',
    'x-caller-trace-id': crypto.randomBytes(8).toString('hex'),
  };
  const resp = await fetch(HEALTH_API + pathname, {
    method,
    headers,
    body: bodyObj ? JSON.stringify(bodyObj) : undefined,
  });
  const text = await resp.text();
  if (!resp.ok) {
    let detail = text;
    try { detail = JSON.parse(text); } catch (e) {}
    const err = new Error('health api ' + resp.status);
    err.status = resp.status;
    err.detail = detail;
    throw err;
  }
  try { return JSON.parse(text); } catch (e) { return { raw: text }; }
}

// 聚合拉取用户当日健康数据
async function fetchHealthSummary(accessToken) {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  const dayStr = `${y}${m}${d}`;
  const out = { date: dayStr, source: 'huawei-health' };

  // 1) 日常活动统计：步数 / 消耗卡路里 / 活动时长
  try {
    out.activity = await callHealthApi('/healthkit/v2/sampleSet:dailyActivitySummary', 'POST', accessToken, {
      startDay: dayStr, endDay: dayStr, timeZone: '+0800',
    });
  } catch (e) { out.activityError = e.message; }

  // 2) 最新体重
  try {
    out.weight = await callHealthApi(
      '/healthkit/v2/sampleSets/latestSamplePoint?dataType=' + encodeURIComponent('体重'),
      'GET', accessToken
    );
  } catch (e) { out.weightError = e.message; }

  // 3) 最新心率（静息/当前）
  try {
    out.heartRate = await callHealthApi(
      '/healthkit/v2/sampleSets/latestSamplePoint?dataType=' + encodeURIComponent('心率'),
      'GET', accessToken
    );
  } catch (e) { out.heartRateError = e.message; }

  return out;
}

// ---------- HTTP 小工具 ----------
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

// ---------- 静态文件托管 ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
};

function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === '/' || rel === '') rel = '/index.html';
  // 防目录穿越
  const safe = path.normalize(rel).replace(/^(\.\.[/\\])+/, '');
  let filePath = path.join(DIST, safe);
  if (!filePath.startsWith(DIST)) {
    res.writeHead(403); res.end('forbidden'); return;
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    // SPA 回退到 index.html
    filePath = path.join(DIST, 'index.html');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('not found'); return; }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------- 路由 ----------
const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, `http://localhost:${PORT}`);
  const p = parsed.pathname;

  // ===== AI 中转代理（密钥仅在后端环境变量，前端不再触碰）=====
  // 用户无需在 App 内填写任何密钥；后端默认用智谱 GLM-4-Flash（免费），也可切 DeepSeek / 豆包。
  if (p === '/api/ai/chat') {
    applyCors(res, req);
    // AI 网关是公开代理（不依赖 Cookie），允许任何网页/iOS/本地文件来源访问，避免 CloudStudio 等动态域名被 CORS 拦截
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
    if (req.method !== 'POST') return sendJson(res, 405, { error: 'method not allowed' });
    let buf = '';
    req.on('data', c => { buf += c; if (buf.length > 5e6) req.destroy(); }); // 5MB 上限，足够带大段上下文的 systemPrompt
    req.on('end', async () => {
      let reqBody;
      try { reqBody = JSON.parse(buf); } catch (e) { return sendJson(res, 400, { error: '请求体不是合法 JSON' }); }
      const { provider, model, system, user } = reqBody;
      if (!user) return sendJson(res, 400, { error: '缺少 user 内容' });

      // 默认智谱 GLM-4-Flash（免费）；前端可指定 provider 覆盖
      const prov = provider || CFG.aiProvider;
      let url, key, mdl;
      if (prov === 'zhipu') {
        if (!CFG.zhipuKey) return sendJson(res, 503, { error: '后端未配置智谱 API Key (ZHIPU_API_KEY)' });
        url = 'https://open.bigmodel.cn/api/paas/v4/chat/completions';
        key = CFG.zhipuKey;
        mdl = model || CFG.zhipuModel;
      } else if (prov === 'doubao') {
        if (!CFG.doubaoKey) return sendJson(res, 503, { error: '后端未配置豆包 API Key' });
        url = 'https://ark.cn-beijing.volces.com/api/v3/chat/completions';
        key = CFG.doubaoKey;
        mdl = model || CFG.doubaoEndpoint || 'doubao-seed-1-6-250615';
      } else {
        if (!CFG.deepseekKey) return sendJson(res, 503, { error: '后端未配置 DeepSeek API Key' });
        url = 'https://api.deepseek.com/chat/completions';
        key = CFG.deepseekKey;
        mdl = model || 'deepseek-chat';
      }

      try {
        // 后端→AI 厂商的 fetch 加 40s 超时（AI cold start 慢）
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 40000);
        const r = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
          body: JSON.stringify({
            model: mdl,
            messages: [
              ...(system ? [{ role: 'system', content: system }] : []),
              { role: 'user', content: user }
            ],
            stream: false, temperature: 0.7
          }),
          signal: ctrl.signal,
        });
        clearTimeout(timer);
        const txt = await r.text();
        // 把厂商响应透传，但保证 Content-Type 是 JSON（即使厂商返 5xx HTML 也包装成 JSON 让前端能解析诊断）
        res.writeHead(r.status, { 'Content-Type': 'application/json; charset=utf-8' });
        if (r.ok) {
          res.end(txt);
        } else {
          // 包装错误：让前端能看到真实状态码 + 厂商错误信息
          let parsed = txt;
          try { parsed = JSON.parse(txt); } catch (_) {}
          res.end(JSON.stringify({ error: 'AI 厂商 ' + r.status + '：' + (typeof parsed === 'string' ? parsed.slice(0, 200) : (parsed.error || parsed.message || JSON.stringify(parsed).slice(0, 200))) }));
        }
      } catch (e) {
        const msg = (e && e.name === 'AbortError') ? 'AI 厂商调用超时（>40s）' : ('AI 网关调用失败: ' + (e.message || e));
        return sendJson(res, 502, { error: msg });
      }
    });
    return;
  }

  // 跨域预检
  if (req.method === 'OPTIONS') {
    applyCors(res, req);
    res.writeHead(204);
    return res.end();
  }
  // 对所有 /api/ 响应附加 CORS 头（允许配置的前端来源携带凭据访问）
  if (p.startsWith('/api/')) applyCors(res, req);

  try {
    // 健康检查
    if (p === '/api/health/ping') {
      return sendJson(res, 200, { ok: true, configured: !!(CFG.clientId && CFG.clientSecret) });
    }

    // 1) 发起授权：重定向到华为登录页
    if (p === '/api/health/login') {
      if (!CFG.clientId || !CFG.clientSecret) {
        return sendJson(res, 500, { error: '后端未配置 HW_CLIENT_ID / HW_CLIENT_SECRET，请在 .env 或环境变量中填写' });
      }
      const redirectUri = resolveRedirectUri(req);
      const state = crypto.randomBytes(8).toString('hex');
      // state 附带 redirectUri，回调时用于精确换 token（避免部署域名与登记不一致）
      const authUrl = AUTH_BASE + '?' + new URLSearchParams({
        response_type: 'code',
        client_id: CFG.clientId,
        redirect_uri: redirectUri,
        scope: SCOPE,
        state: state + '|' + encodeURIComponent(redirectUri),
        access_type: 'offline',
        display: 'touch',
      }).toString();
      return redirect(res, authUrl);
    }

    // 2) 华为授权回调：用 code 换 token，存会话，跳回前端
    if (p === '/api/health/callback') {
      applyCors(res, req);
      const code = parsed.searchParams.get('code');
      const err = parsed.searchParams.get('error');
      const stateRaw = parsed.searchParams.get('state') || '';
      // 从 state 还原换取 token 用的 redirectUri（与发起授权时一致）
      let redirectUri = resolveRedirectUri(req);
      const stateParts = stateRaw.split('|');
      if (stateParts[1]) {
        try { redirectUri = decodeURIComponent(stateParts[1]); } catch (e) {}
      }
      const front = CFG.frontendOrigin || (`${parsed.protocol}//${parsed.host}`);
      if (err) {
        return redirect(res, front + '/?hw=error&reason=' + encodeURIComponent(err) + '#fitness');
      }
      if (!code) {
        return redirect(res, front + '/?hw=error&reason=no_code#fitness');
      }
      try {
        const token = await exchangeToken(code, redirectUri);
        const sid = genSid();
        sessions.set(sid, {
          accessToken: token.access_token,
          refreshToken: token.refresh_token,
          expiresAt: Date.now() + (token.expires_in || 3600) * 1000,
          openId: token.openid || null,
        });
        setCookie(res, 'hk_sid', sid);
        return redirect(res, front + '/?hw=authorized#fitness');
      } catch (e) {
        return redirect(res, front + '/?hw=error&reason=' + encodeURIComponent(e.message) + '#fitness');
      }
    }

    // 3) 拉取健康数据（需已授权）
    if (p === '/api/health/data') {
      const sid = getCookie(req, 'hk_sid');
      const sess = sid && sessions.get(sid);
      if (!sess) {
        return sendJson(res, 401, { error: '未授权，请先访问 /api/health/login 授权' });
      }
      try {
        const at = await ensureAccessToken(sess);
        const summary = await fetchHealthSummary(at);
        return sendJson(res, 200, summary);
      } catch (e) {
        return sendJson(res, 502, { error: e.message, detail: e.detail || null });
      }
    }

    // 4) 撤销授权（清除会话）
    if (p === '/api/health/logout') {
      const sid = getCookie(req, 'hk_sid');
      if (sid) sessions.delete(sid);
      setCookie(res, 'hk_sid', '', 0);
      return sendJson(res, 200, { ok: true });
    }

    // 其余 → 静态文件
    return serveStatic(req, res, p);
  } catch (e) {
    sendJson(res, 500, { error: e.message });
  }
});

server.listen(PORT, () => {
  console.log(`[雨婷工作台] 服务已启动: http://localhost:${PORT}`);
  if (!CFG.clientId || !CFG.clientSecret) {
    console.warn('[警告] 未检测到 HW_CLIENT_ID / HW_CLIENT_SECRET，华为授权功能不可用，请配置 .env 或环境变量');
  }
  console.log('[回调地址] 自动按部署域名生成: /api/health/callback（需在华为开发者联盟登记为该应用的回调地址）');
  if (CFG.frontendOrigin) console.log('[前端来源]', CFG.frontendOrigin);
  const aiStatus = [];
  if (CFG.zhipuKey) aiStatus.push('智谱');
  if (CFG.deepseekKey) aiStatus.push('DeepSeek');
  if (CFG.doubaoKey) aiStatus.push('豆包');
  if (aiStatus.length) console.log('[AI 服务] 已配置：' + aiStatus.join('、') + '（默认 ' + CFG.aiProvider + '）');
  else console.warn('[警告] 未检测到 ZHIPU_API_KEY / DEEPSEEK_API_KEY / DOUBAO_API_KEY，AI 功能不可用');
});

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
  // 默认走智谱 GLM-4-Flash（ZHIPU_MODEL 可配，默认 glm-4-flash）；gemini/deepseek/doubao 保留为备选
  // 注：Gemini 新用户已停用 gemini-2.5-flash 且免费额度为 0，故默认回退智谱
  aiProvider: process.env.AI_PROVIDER || 'zhipu',
  geminiKey: process.env.GEMINI_API_KEY || '',
  geminiModel: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
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

// ========== 每日资讯简报：真实热点新闻 + AI摘要 ==========

// 新闻源配置：多个免费中文新闻API/RSS
const NEWS_SOURCES = {
  // 新浪热点（综合）
  sinaHot: {
    url: 'https://feed.mix.sina.com.cn/api/roll/get?pageid=155&lid=2509&num=30&versionNumber=1.2.4',
    parser: parseSinaRoll,
    category: 'general',
  },
  // 新浪科技
  sinaTech: {
    url: 'https://feed.mix.sina.com.cn/api/roll/get?pageid=155&lid=2514&num=20&versionNumber=1.2.4',
    parser: parseSinaRoll,
    category: 'tech',
  },
  // 新浪财经
  sinaFinance: {
    url: 'https://feed.mix.sina.com.cn/api/roll/get?pageid=155&lid=2515&num=20&versionNumber=1.2.4',
    parser: parseSinaRoll,
    category: 'finance',
  },
  // 新浪体育
  sinaSports: {
    url: 'https://feed.mix.sina.com.cn/api/roll/get?pageid=155&lid=2512&num=15&versionNumber=1.2.4',
    parser: parseSinaRoll,
    category: 'sports',
  },
  // 新浪娱乐
  sinaEnt: {
    url: 'https://feed.mix.sina.com.cn/api/roll/get?pageid=155&lid=2513&num=15&versionNumber=1.2.4',
    parser: parseSinaRoll,
    category: 'ent',
  },
};

// 解析新浪 roll 接口返回的 JSON
function parseSinaRoll(json) {
  const out = [];
  try {
    const list = json.result && json.result.data;
    if (!Array.isArray(list)) return out;
    for (const item of list) {
      if (item.title && item.url) {
        out.push({
          title: item.title.replace(/<[^>]*>/g, '').trim(),
          url: item.url,
          source: item.source || item.media_name || '新浪新闻',
        });
      }
    }
  } catch (e) { /* ignore */ }
  return out;
}

// 行业分类关键词映射（用于将通用热点归类到6大行业）
const CATEGORY_KEYWORDS = {
  '💻科技与AI': ['AI','人工智能','芯片','半导体','华为','小米','苹果','谷歌','微软','OpenAI','GPT','大模型','算力','5G','6G','手机','智能','科技','互联网','平台','算法','数据','云计算','区块链','元宇宙','机器人','自动驾驶','特斯拉','电动车','新能源车','电池','光伏','航天','卫星','量子'],
  '🛒大消费与零售': ['消费','零售','电商','淘宝','京东','拼多多','直播带货','奶茶','餐饮','食品','饮料','白酒','啤酒','化妆品','奢侈品','旅游','酒店','航空','电影','票房','游戏','快递','物流','外卖','美团','滴滴','出行','买房','房价','楼市','汽车','销量','促销','打折','免税','跨境电商'],
  '🏥医疗健康': ['医疗','医药','医院','疫苗','新冠','病毒','健康','医保','药品','中药','创新药','生物','基因','体检','养老','生育','三胎','辅助生殖','医美','康养','保险','疾控'],
  '💰金融与宏观': ['A股','港股','美股','股市','央行','利率','降息','加息','通胀','CPI','GDP','经济','财政','税收','人民币','汇率','外汇','债券','基金','银行','贷款','房贷','社保','养老金','失业','就业','薪资','收入','贸易','出口','进口','一带一路','美联储','比特币','数字货币','黄金','原油','期货'],
  '🎬文娱与自媒体': ['综艺','电视剧','偶像','明星','网红','抖音','快手','B站','视频','短视频','直播','热搜','微博','社交','网文','IP','影视','音乐','演唱会','动漫','电竞','游戏','网易游戏','腾讯游戏','Steam'],
  '🏛️政策与监管': ['政策','法规','监管','法律','国务院','部委','发改委','工信部','教育部','住建部','公安部','最高法','最高检','人大','政协','两会','提案','法案','反垄断','处罚','约谈','整改','安全','国安','环保','碳达峰','碳中和','教育改革','房产税','数字'],
};

// 根据标题关键词判断行业分类
function categorizeNews(title) {
  const t = title.toLowerCase();
  let bestCat = '💻科技与AI'; // 默认
  let bestScore = 0;
  for (const [cat, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
    let score = 0;
    for (const kw of keywords) {
      if (t.includes(kw.toLowerCase())) score += kw.length; // 长关键词权重更高
    }
    if (score > bestScore) { bestScore = score; bestCat = cat; }
  }
  return bestCat;
}

// 用 fetch 抓取单个新闻源，带超时
async function fetchNewsSource(srcConfig) {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const resp = await fetch(srcConfig.url + '&_t=' + Date.now(), {
      signal: ctrl.signal,
      headers: { 'Accept': 'application/json', 'User-Agent': 'Mozilla/5.0' },
    });
    clearTimeout(timer);
    if (!resp.ok) return [];
    const json = await resp.json().catch(() => ({}));
    return srcConfig.parser(json);
  } catch (e) {
    console.log('[news] source fetch failed:', srcConfig.url.slice(0, 50), e.message);
    return [];
  }
}

// 调用 AI 生成摘要（复用已有 AI 网关逻辑）
async function aiSummarize(newsItems) {
  // 构建新闻文本供 AI 摘要
  const newsText = newsItems.map((item, i) =>
    `${i + 1}. 【${item.title}】(来源: ${item.source})`
  ).join('\n');

  const sysPrompt = `你是专业的中文新闻编辑。用户会给你一组真实的当日热点新闻标题和来源。
请为每条新闻生成：
1. brief：一句话AI智能摘要（15-35字），精炼概括核心要点，要有信息密度
2. insight：给普通人的启发或行动建议（20-40字）

只输出合法JSON数组，不要markdown代码块，格式：
[{"brief":"...","insight":"..."}]
数组长度必须和输入新闻条数一致，一一对应。`;

  // 选择可用的 AI 提供商
  let prov = CFG.aiProvider;
  let key = '', url = '', mdl = '';

  if (prov === 'zhipu' && CFG.zhipuKey) {
    url = 'https://open.bigmodel.cn/api/paas/v4/chat/completions';
    key = CFG.zhipuKey;
    mdl = CFG.zhipuModel;
  } else if (CFG.deepseekKey) {
    prov = 'deepseek';
    url = 'https://api.deepseek.com/chat/completions';
    key = CFG.deepseekKey;
    mdl = 'deepseek-chat';
  } else if (CFG.doubaoKey) {
    prov = 'doubao';
    url = 'https://ark.cn-beijing.volces.com/api/v3/chat/completions';
    key = CFG.doubaoKey;
    mdl = CFG.doubaoEndpoint || 'doubao-seed-1-6-250615';
  } else if (CFG.geminiKey) {
    prov = 'gemini';
  } else {
    throw new Error('未配置任何 AI API Key，无法生成摘要');
  }

  // Gemini 分支
  if (prov === 'gemini') {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 35000);
    const gRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(CFG.geminiModel)}:generateContent?key=${encodeURIComponent(CFG.geminiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ role: 'user', parts: [{ text: `${sysPrompt}\n\n以下是需要摘要的新闻：\n${newsText}` }] }],
        generationConfig: { temperature: 0.5 },
      }),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    const gJson = await gRes.json().catch(() => ({}));
    if (!gJson.ok) throw new Error('Gemini 摘要失败');
    const text = gJson.candidates?.[0]?.content?.parts?.[0]?.text || '';
    return parseAiSummary(text, newsItems.length);
  }

  // OpenAI 兼容接口分支（智谱/DeepSeek/豆包）
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 35000);
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
    body: JSON.stringify({
      model: mdl,
      messages: [
        { role: 'system', content: sysPrompt },
        { role: 'user', content: `以下是需要摘要的新闻：\n${newsText}` }
      ],
      stream: false, temperature: 0.5,
    }),
    signal: ctrl.signal,
  });
  clearTimeout(timer);

  if (!r.ok) {
    const errText = await r.text().catch(() => '');
    throw new Error('AI摘要API返回 ' + r.status);
  }
  const aiJson = await r.json().catch(() => ({}));
  const text = aiJson.choices?.[0]?.message?.content || '';
  return parseAiSummary(text, newsItems.length);
}

// 解析 AI 返回的摘要 JSON
function parseAiSummary(text, expectedCount) {
  try {
    let cleaned = text.replace(/```json\s*/gi, '').replace(/```\s*$/gi, '').trim();
    // 尝试找到JSON数组
    const arrStart = cleaned.indexOf('[');
    const arrEnd = cleaned.lastIndexOf(']');
    if (arrStart >= 0 && arrEnd > arrStart) {
      cleaned = cleaned.substring(arrStart, arrEnd + 1);
    }
    const arr = JSON.parse(cleaned);
    if (Array.isArray(arr) && arr.length === expectedCount) {
      return arr.map((item, i) => ({
        brief: (item.brief || item.summary || '').slice(0, 100),
        insight: (item.insight || item.advice || '').slice(0, 100),
      }));
    }
  } catch (e) {
    console.log('[news] ai summary parse error:', e.message.slice(0, 100));
  }
  // 解析失败时返回空摘要兜底
  return Array(expectedCount).fill({ brief: '', insight: '' });
}

// 主函数：生成真实新闻简报
async function generateRealNewsBriefing(focus) {
  const isAll = focus === '全行业综合';

  // 1) 并行抓取所有新闻源
  const sourceEntries = Object.entries(NEWS_SOURCES);
  const fetchResults = await Promise.all(
    sourceEntries.map(([name, cfg]) => fetchNewsSource(cfg).then(items => ({ name, items })).catch(() => ({ name, items: [] })))
  );

  // 2) 合并所有新闻并去重（按标题相似度简单去重）
  const allNews = [];
  const seenTitles = new Set();
  for (const { items } of fetchResults) {
    for (const item of items) {
      // 简单去重：标题前15个字符相同视为重复
      const key = item.title.slice(0, 15);
      if (!seenTitles.has(key)) {
        seenTitles.add(key);
        allNews.push(item);
      }
    }
  }

  if (allNews.length === 0) {
    throw new Error('未能获取到任何新闻数据，请稍后重试');
  }

  console.log(`[news] fetched ${allNews.length} unique items from ${fetchResults.filter(r => r.items.length > 0).length} sources`);

  // 3) 分类
  const categorized = {};
  for (const item of allNews) {
    const cat = categorizeNews(item.title);
    if (!categorized[cat]) categorized[cat] = [];
    categorized[cat].push(item);
  }

  // 4) 按需选取内容
  const targetCategories = isAll
    ? ['💻科技与AI', '🛒大消费与零售', '🏥医疗健康', '💰金融与宏观', '🎬文娱与自媒体', '🏛️政策与监管']
    : [`emoji+${focus}`];

  const sections = [];

  if (isAll) {
    // 全行业模式：每个分类选 top 2
    for (const cat of targetCategories) {
      const items = (categorized[cat] || []).slice(0, 2);
      if (items.length > 0) {
        sections.push({ category: cat, rawItems: items });
      }
    }
    // 如果某些分类没有新闻，从多的分类补充
    if (sections.length < 4) {
      const usedCats = new Set(sections.map(s => s.category));
      for (const [cat, items] of Object.entries(categorized)) {
        if (!usedCats.has(cat) && items.length > 0) {
          sections.push({ category: cat, rawItems: items.slice(0, 2) });
          if (sections.length >= 6) break;
        }
      }
    }
  } else {
    // 单行业模式：选 top 3
    const matchedCat = Object.keys(CATEGORY_KEYWORDS).find(k => k.includes(focus));
    const catKey = matchedCat || `emoji+${focus}`;
    const items = (categorized[catKey] || allNews).slice(0, 3);
    if (items.length > 0) {
      sections.push({ category: catKey.includes(focus) ? catKey : `📰${focus}`, rawItems: items });
    }
  }

  if (sections.length === 0) {
    // 最终兜底：直接用前6条不分类
    sections.push({ category: '📰今日热点', rawItems: allNews.slice(0, 6) });
  }

  // 5) 收集所有需要摘要的新闻，批量调用 AI
  const allRawItems = sections.flatMap(s => s.rawItems);
  console.log(`[news] summarizing ${allRawItems.length} news items via AI...`);

  const summaries = await aiSummarize(allRawItems);

  // 6) 组装最终结果
  let summaryIdx = 0;
  const finalSections = sections.map(section => {
    const items = section.rawItems.map((rawItem, i) => {
      const summary = summaries[summaryIdx] || { brief: rawItem.title, insight: '' };
      summaryIdx++;
      return {
        title: rawItem.title,
        url: rawItem.url,
        source: rawItem.source,
        brief: summary.brief || rawItem.title.slice(0, 40),
        insight: summary.insight,
      };
    });
    return { category: section.category, items };
  });

  return {
    subtitle: `今日 · ${formatNewsDateCN(new Date())}`,
    readTime: '约5分钟',
    sections: finalSections,
    version: 6,
    generatedAt: new Date().toISOString(),
    sourceCount: fetchResults.filter(r => r.items.length > 0).length,
    newsCount: allRawItems.length,
  };
}

// 格式化日期（中文风格，服务端用）
function formatNewsDateCN(d) {
  const w = ['周日','周一','周二','周三','周四','周五','周六'][d.getDay()];
  return `${d.getFullYear()}年${d.getMonth()+1}月${d.getDate()}日 · ${w}`;
}

// ---------- 路由 ----------
const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, `http://localhost:${PORT}`);
  const p = parsed.pathname;

  // ===== AI 中转代理（密钥仅在后端环境变量，前端不再触碰）=====
  // 默认走智谱 GLM-4-Flash（ZHIPU_MODEL 可配）；gemini/deepseek/doubao 保留为备选。
  // 所有厂商响应统一映射成 OpenAI 兼容结构 { choices:[{ message:{ content } }] }，前端无需改动。
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

      // 默认智谱；前端可指定 provider 覆盖
      const prov = provider || CFG.aiProvider;

      // ===== Gemini 分支（Google 原生格式，key 走 query 参数，无 Bearer 头）=====
      if (prov === 'gemini') {
        if (!CFG.geminiKey) return sendJson(res, 503, { error: '后端未配置 Gemini API Key (GEMINI_API_KEY)' });
        const mdl = model || CFG.geminiModel;
        try {
          const ctrl = new AbortController();
          const timer = setTimeout(() => ctrl.abort(), 40000);
          const gRes = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(mdl)}:generateContent?key=${encodeURIComponent(CFG.geminiKey)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ role: 'user', parts: [{ text: user }] }],
              ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}),
              generationConfig: { temperature: 0.7 },
            }),
            signal: ctrl.signal,
          });
          clearTimeout(timer);
          const gJson = await gRes.json().catch(() => ({}));
          if (!gRes.ok) {
            const msg = (gJson.error && (gJson.error.message || JSON.stringify(gJson.error))) || ('Gemini ' + gRes.status);
            return sendJson(res, 502, { error: 'Gemini 调用失败: ' + String(msg).slice(0, 220) });
          }
          const text = gJson.candidates && gJson.candidates[0] && gJson.candidates[0].content && gJson.candidates[0].content.parts && gJson.candidates[0].content.parts[0] && gJson.candidates[0].content.parts[0].text;
          if (!text) return sendJson(res, 502, { error: 'Gemini 返回为空（可能触发了安全过滤或无候选结果）' });
          // 映射成 OpenAI 兼容结构，前端 callAI 无需改动
          return sendJson(res, 200, { choices: [{ message: { content: text } }], model: mdl });
        } catch (e) {
          const msg = (e && e.name === 'AbortError') ? 'Gemini 调用超时（>40s）' : ('Gemini 网关调用失败: ' + (e.message || e));
          return sendJson(res, 502, { error: msg });
        }
      }

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

    // 5) 用户健康数据云端存取（跨设备同步，文件存储）
    //    GET  /api/userdata        → 返回云端数据
    //    POST /api/userdata        → 保存云端数据（整体覆盖）
    if (p === '/api/userdata') {
      applyCors(res, req);
      res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

      const dataFile = path.join(__dirname, 'userdata.json');

      if (req.method === 'GET') {
        try {
          if (fs.existsSync(dataFile)) {
            const raw = fs.readFileSync(dataFile, 'utf-8');
            return sendJson(res, 200, JSON.parse(raw));
          }
          return sendJson(res, 200, { ok: true, data: null, message: '暂无云端数据' });
        } catch (e) {
          return sendJson(res, 500, { error: '读取云端数据失败: ' + e.message });
        }
      }

      if (req.method === 'POST') {
        let buf = '';
        req.on('data', c => { buf += c; if (buf.length > 2e6) req.destroy(); });
        req.on('end', () => {
          try {
            const parsed = JSON.parse(buf);
            // 加上最后同步时间
            parsed.cloudSyncedAt = new Date().toISOString();
            fs.writeFileSync(dataFile, JSON.stringify(parsed, null, 2), 'utf-8');
            return sendJson(res, 200, { ok: true, cloudSyncedAt: parsed.cloudSyncedAt });
          } catch (e) {
            return sendJson(res, 400, { error: '保存失败: ' + e.message });
          }
        });
        return;
      }
    }

    // 6) 每日资讯简报：抓取真实热点新闻 + AI生成摘要
    //    GET /api/news?focus=全行业综合&fresh=1
    //    流程：多源爬取真实新闻 → 按行业分类去重 → AI摘要 → 返回含真实URL的结构化简报
    if (p === '/api/news') {
      applyCors(res, req);
      res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
      if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed' });

      const focus = parsed.searchParams.get('focus') || '全行业综合';
      const fresh = parsed.searchParams.has('fresh');

      try {
        const result = await generateRealNewsBriefing(focus);
        return sendJson(res, 200, result);
      } catch (e) {
        console.error('[/api/news] error:', e.message);
        return sendJson(res, 502, { error: '简报生成失败: ' + e.message });
      }
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

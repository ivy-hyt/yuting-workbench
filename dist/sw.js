// 雨婷工作台 Service Worker — 离线缓存
const CACHE_NAME = 'yuting-workbench-v22';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './icon-96.png',
  './icon-144.png',
  './icon-192.png',
  './icon-512.png',
  './apple-touch-icon.png'
];

// 安装：预缓存核心资源
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

// 激活：清理旧缓存
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// 抓取：API 永远透传（不吞错误）；静态资源 network-first
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // ===== API：永远直接走网络，不拦截、不吞错误 =====
  // 旧版本会 catch 所有 fetch 错误返 503 offline，把 AI 调用失败的
  // 真实原因（CORS / 后端错误 / 超时）全吞了，让用户看不到诊断。
  // 这里改为：完全透传给前端，AI 失败时前端能拿到真实状态码与响应体。
  if (url.pathname.startsWith('/api/')) {
    // 不调用 event.respondWith，让浏览器按默认行为走网络
    return;
  }

  if (event.request.method !== 'GET') return;

  // HTML 导航请求：network-first，保证部署新版本后内容及时生效
  const isNav = event.request.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html');
  if (isNav) {
    event.respondWith(
      fetch(event.request)
        .then((resp) => {
          if (resp.status === 200) {
            const copy = resp.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          }
          return resp;
        })
        .catch(() => caches.match(event.request).then((c) => c || caches.match('./index.html')))
    );
    return;
  }
  // 其他同源静态资源：缓存优先，支持离线
  event.respondWith(
    caches.match(event.request)
      .then((cached) => {
        if (cached) return cached;
        return fetch(event.request)
          .then((resp) => {
            if (url.origin === self.location.origin && resp.status === 200) {
              const copy = resp.clone();
              caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
            }
            return resp;
          })
          .catch(() => caches.match('./index.html'));
      })
  );
});
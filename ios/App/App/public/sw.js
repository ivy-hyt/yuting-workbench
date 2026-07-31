// 雨婷工作台 Service Worker — 离线缓存
const CACHE_NAME = 'yuting-workbench-v2';
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

// 抓取：缓存优先，回退网络，再回退离线页
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  // API 请求：始终走网络，不缓存，保证华为健康数据实时
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(event.request).catch(() => new Response(
        JSON.stringify({ error: 'offline', message: '网络不可用，无法同步数据' }),
        { status: 503, headers: { 'Content-Type': 'application/json' } }
      ))
    );
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

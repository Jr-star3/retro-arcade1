self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  // Ready to control clients
});

self.addEventListener('fetch', event => {
  // Default: just pass through
});

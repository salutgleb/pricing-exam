'use strict';
// Расшифровывает сайт на лету: запросы к /<repo>/v/... превращаются в
// чтение зашифрованных кусков из d/<id>.bin и отдаются браузеру как обычные файлы.
const BASE = new URL('./', self.location).pathname;
const VIRTUAL = BASE + 'v/';
const BLOB_EXT = '.zip'; // .bin GitHub Pages сжимает gzip'ом и ломает Range
const TAG_BYTES = 16;
const CHUNKS_PER_FETCH = 4;
const DB_NAME = 'private-site:' + BASE; // у каждого сайта на домене своё хранилище ключа
const STORE = 'keys';

let state = null;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
self.addEventListener('message', (event) => {
  if (event.data === 'reset') state = null;
});
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(VIRTUAL)) return;
  event.respondWith(
    serve(event.request, url).catch((error) => new Response('Не получилось открыть файл: ' + error.message, {
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })),
  );
});

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function storeRequest(mode, action) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const request = action(db.transaction(STORE, mode).objectStore(STORE));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

const fromHex = (text) => new Uint8Array(text.match(/../g).map((byte) => parseInt(byte, 16)));

function chunkIv(nonce, index) {
  const iv = new Uint8Array(12);
  iv.set(nonce);
  new DataView(iv.buffer).setUint32(8, index);
  return iv;
}

async function loadKey() {
  const stored = await storeRequest('readonly', (store) => store.get('key'));
  if (!stored) return null;
  if (stored instanceof CryptoKey) return stored;
  if (stored.raw) return crypto.subtle.importKey('raw', stored.raw, 'AES-GCM', false, ['decrypt']);
  return null;
}

async function fetchChunks(url, nonce, size, chunk, first, last, key) {
  const encryptedChunk = chunk + TAG_BYTES;
  const encryptedSize = size + Math.ceil(size / chunk) * TAG_BYTES;
  const start = first * encryptedChunk;
  const end = Math.min((last + 1) * encryptedChunk, encryptedSize) - 1;
  const response = await fetch(url, { headers: { Range: `bytes=${start}-${end}` } });
  if (!response.ok) throw new Error('сервер ответил ' + response.status);
  let buffer = await response.arrayBuffer();
  if (response.status === 200) buffer = buffer.slice(start, end + 1);
  const parts = [];
  for (let index = first, offset = 0; index <= last; index += 1) {
    const length = Math.min(encryptedChunk, buffer.byteLength - offset);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: chunkIv(nonce, index) }, key, buffer.slice(offset, offset + length),
    );
    parts.push(new Uint8Array(plain));
    offset += length;
  }
  return parts;
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  parts.reduce((offset, part) => { out.set(part, offset); return offset + part.length; }, 0);
  return out;
}

async function getState() {
  if (state) return state;
  const key = await loadKey();
  if (!key) return null;
  const gate = await (await fetch(BASE + 'gate.json', { cache: 'no-cache' })).json();
  const { nonce, size } = gate.manifest;
  try {
    const last = Math.ceil(size / gate.chunk) - 1;
    const parts = await fetchChunks(BASE + 'm' + BLOB_EXT, fromHex(nonce), size, gate.chunk, 0, last, key);
    state = { key, gate, files: JSON.parse(new TextDecoder().decode(concat(parts))).files };
    return state;
  } catch (error) {
    // Ключ стираем, только если он не подходит к данным (сменили пароль); сетевые сбои пробрасываем.
    if (error.name !== 'OperationError') throw error;
    await storeRequest('readwrite', (store) => store.delete('key'));
    return null;
  }
}

function parseRange(header, size) {
  const match = /bytes=(\d*)-(\d*)/.exec(header || '');
  if (!match) return null;
  if (match[1] === '') return { start: Math.max(0, size - Number(match[2])), end: size - 1 };
  const end = match[2] === '' ? size - 1 : Math.min(Number(match[2]), size - 1);
  return { start: Number(match[1]), end };
}

async function serve(request, url) {
  const current = await getState();
  if (!current) {
    const next = url.pathname.slice(VIRTUAL.length) + url.search;
    return Response.redirect(BASE + '?next=' + encodeURIComponent(next), 302);
  }
  let rel = decodeURIComponent(url.pathname.slice(VIRTUAL.length)).normalize('NFC');
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  let entry = current.files[rel];
  let status = 200;
  if (!entry) {
    entry = current.files['404.html'];
    status = 404;
  }
  const [id, size, nonce, type] = entry;
  const headers = new Headers({
    'Content-Type': type,
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'no-store',
  });
  let start = 0;
  let end = size - 1;
  const range = status === 200 ? parseRange(request.headers.get('range'), size) : null;
  if (range) {
    if (range.start >= size) {
      return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${size}` } });
    }
    ({ start, end } = range);
    status = 206;
    headers.set('Content-Range', `bytes ${start}-${end}/${size}`);
  }
  headers.set('Content-Length', String(size === 0 ? 0 : end - start + 1));
  if (request.method === 'HEAD' || size === 0) return new Response(null, { status, headers });
  return new Response(decryptStream(current, id, nonce, size, start, end), { status, headers });
}

function decryptStream(current, id, nonceHex, size, start, end) {
  const { chunk } = current.gate;
  const nonce = fromHex(nonceHex);
  const url = BASE + 'd/' + id + BLOB_EXT;
  const last = Math.floor(end / chunk);
  let next = Math.floor(start / chunk);
  return new ReadableStream({
    async pull(controller) {
      if (next > last) {
        controller.close();
        return;
      }
      const upto = Math.min(last, next + CHUNKS_PER_FETCH - 1);
      const parts = await fetchChunks(url, nonce, size, chunk, next, upto, current.key);
      parts.forEach((part, offset) => {
        const from = (next + offset) * chunk;
        controller.enqueue(part.subarray(Math.max(start - from, 0), Math.min(end - from + 1, part.length)));
      });
      next = upto + 1;
    },
  });
}

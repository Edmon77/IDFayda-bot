/**
 * Shared HTTP client for Fayda API with keep-alive connections,
 * DNS caching, and response compression.
 *
 * Optimizations:
 *   - keep-alive:   Reuses TCP connections across requests
 *   - DNS caching:  Avoids redundant DNS lookups (cacheable-lookup)
 *   - compression:  Requests gzip/deflate responses (~60-70% smaller PDF payloads)
 */
const axios = require('axios');
const http = require('http');
const https = require('https');
const CacheableLookup = require('cacheable-lookup');

const API_BASE = 'https://api-resident.fayda.et';
const HEADERS = {
  'Content-Type': 'application/json',
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Origin': 'https://resident.fayda.et',
  'Referer': 'https://resident.fayda.et/',
  'Accept-Encoding': 'gzip, deflate, br'
};

// DNS caching — avoids repeated DNS lookups for api-resident.fayda.et
const cacheable = new CacheableLookup();

const httpAgent = new http.Agent({ keepAlive: true });
const httpsAgent = new https.Agent({ keepAlive: true });

// Install DNS cache on both agents
cacheable.install(httpAgent);
cacheable.install(httpsAgent);

const api = axios.create({
  baseURL: API_BASE,
  timeout: 35000,
  httpAgent,
  httpsAgent,
  headers: HEADERS,
  decompress: true    // auto-decompress gzip/deflate/br responses
});

module.exports = { api, API_BASE, HEADERS };

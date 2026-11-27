const admin = require('firebase-admin');
const MAX_REQUESTS_PER_MINUTE = 20;
const WINDOW_MS = 60000;
const MAX_MAP_SIZE = 10000;
const ALLOWED_ORIGIN = 'https://www.creatorweb.cc';
const rateLimits = new Map();
let dbInstance = null;
let initError = null;
const getDb = () => {
    if (dbInstance) return dbInstance;
    if (!admin.apps.length) {
        try {
            const rawCreds = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;
            if (!rawCreds) throw new Error('Missing credentials');
            const serviceAccount = JSON.parse(rawCreds);
            if (!serviceAccount.project_id || !serviceAccount.client_email || !serviceAccount.private_key) {
                throw new Error('Invalid service account schema');
            }
            admin.initializeApp({
                credential: admin.credential.cert(serviceAccount)
            });
            initError = null;
        } catch (e) {
            initError = e;
            return null;
        }
    }
    dbInstance = admin.firestore();
    return dbInstance;
};
const sanitizeText = (input, maxLength = 256) => {
    if (typeof input !== 'string') return '';
    return input
        .replace(/[\u0000-\u001F\u007F]/g, '')
        .replace(/[<>&"'`]/g, '')
        .trim()
        .slice(0, maxLength);
};
const sanitizeUrl = (input) => {
    if (typeof input !== 'string') return null;
    const cleaned = input.replace(/[\u0000-\u001F\u007F\s]/g, '').slice(0, 2048);
    try {
        const parsed = new URL(cleaned);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
        if (['localhost', '127.0.0.1', '0.0.0.0', '::1'].includes(parsed.hostname.toLowerCase())) return null;
        return parsed.toString();
    } catch {
        return null;
    }
};
const extractClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length > 0) {
        const firstIp = forwarded.split(',')[0].trim();
        if (/^[a-fA-F0-9:.]{3,45}$/.test(firstIp)) return firstIp;
    }
    const cfIp = req.headers['cf-connecting-ip'];
    if (typeof cfIp === 'string' && /^[a-fA-F0-9:.]{3,45}$/.test(cfIp.trim())) {
        return cfIp.trim();
    }
    const remote = req.socket && req.socket.remoteAddress ? String(req.socket.remoteAddress) : '';
    return /^[a-fA-F0-9:.]{3,45}$/.test(remote) ? remote : 'unknown';
};
const pruneRateLimits = (now) => {
    if (rateLimits.size <= MAX_MAP_SIZE) return;
    for (const [key, entry] of rateLimits.entries()) {
        if (now - entry.time > WINDOW_MS) {
            rateLimits.delete(key);
        }
    }
    while (rateLimits.size > MAX_MAP_SIZE) {
        const oldestKey = rateLimits.keys().next().value;
        if (!oldestKey) break;
        rateLimits.delete(oldestKey);
    }
};
const isRateLimited = (ip) => {
    const now = Date.now();
    pruneRateLimits(now);
    const existing = rateLimits.get(ip);
    if (!existing || now - existing.time > WINDOW_MS) {
        rateLimits.set(ip, { count: 1, time: now });
        return false;
    }
    existing.count += 1;
    rateLimits.set(ip, existing);
    return existing.count > MAX_REQUESTS_PER_MINUTE;
};
const delay = (ms) => new Promise((res) => setTimeout(res, ms));
const setSecurityHeaders = (req, res) => {
    const origin = req.headers.origin;
    if (origin === ALLOWED_ORIGIN) {
        res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
        res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Cache-Control', 'no-store, max-age=0');
};
export default async function handler(req, res) {
    setSecurityHeaders(req, res);
    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }
    if (req.method !== 'GET') {
        res.setHeader('Allow', 'GET, OPTIONS');
        return res.status(405).json({ error: 'Metodo non consentito. Usa GET.' });
    }
    const clientIp = extractClientIp(req);
    if (isRateLimited(clientIp)) {
        await delay(1500);
        return res.status(429).json({ error: 'Troppe richieste. Riprova tra 1 minuto.' });
    }
    try {
        const db = getDb();
        if (!db || initError) {
            return res.status(503).json({ error: 'Servizio temporaneamente non disponibile' });
        }
        const statusRef = db.collection('stato del servizio').doc('current_status');
        const doc = await statusRef.get();
        if (!doc.exists) {
            return res.status(404).json({ error: 'Dato non trovato nel database' });
        }
        const rawData = doc.data() || {};
        const safeResponse = {
            stato: sanitizeText(rawData.stato, 128),
            link_responsabilita: sanitizeUrl(rawData.link_responsabilita)
        };
        return res.status(200).json(safeResponse);
    } catch {
        return res.status(500).json({ error: 'Errore interno del server' });
    }
}

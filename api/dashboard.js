const crypto = require('crypto');
const admin = require('firebase-admin');

const ALLOWED_ORIGIN = 'https://www.creatorweb.cc';
const MAX_RATE_BUCKETS = 5000;
const SENSITIVE_KEYS = new Set([
    'password',
    'passwordHash',
    'password_hash',
    'codici_sicurezza_hash',
    'totpSecret',
    'totp_secret',
    'recoveryCodes',
    'recovery_codes',
    'apiKey',
    'api_key',
    'token',
    'refreshToken',
    'refresh_token',
    'role',
    'roles',
    'isAdmin',
    'is_admin',
    'permissions'
]);
const rateLimits = new Map();

if (!admin.apps.length) {
    const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;
    if (!rawServiceAccount) throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_WORK');
    let serviceAccount;
    try {
        serviceAccount = typeof rawServiceAccount === 'string'
            ? JSON.parse(rawServiceAccount)
            : rawServiceAccount;
    } catch (_error) {
        throw new Error('FIREBASE_SERVICE_ACCOUNT_WORK non contiene un JSON valido');
    }
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}

const db = admin.firestore();

function setSecurityHeaders(req, res) {
    const origin = req.headers.origin;
    if (origin === ALLOWED_ORIGIN) res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
}

function getClientKey(req) {
    const rawIp = req.socket?.remoteAddress || 'unknown';
    const cleanIp = rawIp.replace(/^::ffff:/, '').slice(0, 64);
    const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
    const tokenMatch = authHeader.match(/^Bearer\s+(\S+)$/i);
    if (!tokenMatch) return `ip:${cleanIp}`;
    const tokenHash = crypto.createHash('sha256').update(tokenMatch[1]).digest('hex').slice(0, 16);
    return `ip:${cleanIp}:tok:${tokenHash}`;
}

function pruneRateLimits(now) {
    for (const [key, entry] of rateLimits.entries()) {
        if (now - entry.startedAt >= 60000) rateLimits.delete(key);
    }
    if (rateLimits.size >= MAX_RATE_BUCKETS) {
        const oldestKey = rateLimits.keys().next().value;
        if (oldestKey) rateLimits.delete(oldestKey);
    }
}

function rateLimited(req) {
    const now = Date.now();
    if (rateLimits.size > 250 || rateLimits.size >= MAX_RATE_BUCKETS) pruneRateLimits(now);
    const key = getClientKey(req);
    const current = rateLimits.get(key) || { count: 0, startedAt: now };
    if (now - current.startedAt >= 60000) {
        current.count = 0;
        current.startedAt = now;
    }
    current.count += 1;
    rateLimits.set(key, current);
    return current.count > 60;
}

function isPlainObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === null || proto === Object.prototype;
}

async function requireCustomer(req) {
    const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
    const match = authHeader.match(/^Bearer\s+([A-Za-z0-9\-_.]+)$/);
    if (!match || match[1].length > 4096) {
        const error = new Error('Autenticazione richiesta. Accedi nuovamente.');
        error.status = 401;
        throw error;
    }

    let decoded;
    try {
        decoded = await admin.auth().verifyIdToken(match[1], true);
    } catch (_error) {
        const error = new Error('Sessione non valida o scaduta.');
        error.status = 401;
        throw error;
    }

    if (!decoded?.uid || decoded.firebase?.sign_in_provider === 'anonymous') {
        const error = new Error('Sessione non autorizzata.');
        error.status = 403;
        throw error;
    }

    const userRef = db.collection('utenti_dashboard').doc(decoded.uid);
    const snapshot = await userRef.get();
    if (!snapshot.exists) {
        const error = new Error('Profilo non trovato. Contatta l’amministratore.');
        error.status = 404;
        throw error;
    }

    const profile = snapshot.data() || {};
    if (profile.account?.disabled === true || profile.account?.suspended === true) {
        const error = new Error('Account sospeso. Contatta l’amministratore.');
        error.status = 403;
        throw error;
    }
    if (profile.account?.must_change_password === true) {
        const error = new Error('Prima di accedere alla dashboard devi modificare la password temporanea.');
        error.status = 403;
        error.code = 'PASSWORD_CHANGE_REQUIRED';
        throw error;
    }
    return { uid: decoded.uid, profile };
}

function cleanString(value, maxLength = 3000) {
    if (typeof value !== 'string') return '';
    return value
        .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
        .trim()
        .replace(/[<>]/g, '')
        .slice(0, maxLength);
}

function cleanUrl(value, maxLength = 1000) {
    const cleaned = cleanString(value, maxLength);
    if (!cleaned) return '';
    const candidate = /^https?:\/\//i.test(cleaned) ? cleaned : `https://${cleaned}`;
    try {
        const parsed = new URL(candidate);
        if (!['http:', 'https:'].includes(parsed.protocol)) return '';
        if (!parsed.hostname || parsed.hostname === 'localhost' || parsed.hostname.endsWith('.local')) return '';
        return parsed.toString().slice(0, maxLength);
    } catch (_error) {
        return '';
    }
}

function sanitizeData(value, depth = 0) {
    if (depth > 8) return null;
    if (value === null || value === undefined) return null;
    if (typeof value === 'boolean' || typeof value === 'number') {
        return Number.isFinite(value) ? value : null;
    }
    if (typeof value === 'string') {
        return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').slice(0, 10000);
    }
    if (typeof value.toDate === 'function') {
        try {
            return value.toDate().toISOString();
        } catch (_error) {
            return null;
        }
    }
    if (Array.isArray(value)) {
        return value.slice(0, 200).map((item) => sanitizeData(item, depth + 1));
    }
    if (typeof value === 'object') {
        const result = Object.create(null);
        for (const [key, child] of Object.entries(value)) {
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
            if (SENSITIVE_KEYS.has(key)) continue;
            result[key] = sanitizeData(child, depth + 1);
        }
        return result;
    }
    return null;
}

function toTimestampMs(value) {
    if (!value) return 0;
    if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
    const ms = new Date(value).getTime();
    return Number.isFinite(ms) ? ms : 0;
}

module.exports = async function handler(req, res) {
    setSecurityHeaders(req, res);
    if (req.method === 'OPTIONS') return res.status(204).end();

    const origin = req.headers.origin;
    if (origin && origin !== ALLOWED_ORIGIN) {
        return res.status(403).json({ error: 'Origin non autorizzata' });
    }
    if (req.method !== 'GET' && req.method !== 'POST') {
        return res.status(405).json({ error: 'Metodo non consentito' });
    }
    if (rateLimited(req)) {
        res.setHeader('Retry-After', '60');
        return res.status(429).json({ error: 'Troppe richieste. Riprova più tardi.' });
    }

    try {
        const { uid, profile } = await requireCustomer(req);

        if (req.method === 'GET') {
            const [allCommsSnapshot, userCommsSnapshot] = await Promise.all([
                db.collection('comunicazioni')
                    .where('published', '==', true)
                    .where('targetType', '==', 'all')
                    .limit(100)
                    .get(),
                db.collection('comunicazioni')
                    .where('published', '==', true)
                    .where('targetType', '==', 'user')
                    .where('targetUid', '==', uid)
                    .limit(100)
                    .get()
            ]);

            const deduped = new Map();
            for (const doc of [...allCommsSnapshot.docs, ...userCommsSnapshot.docs]) {
                if (!deduped.has(doc.id)) {
                    deduped.set(doc.id, {
                        id: doc.id,
                        ...sanitizeData(doc.data())
                    });
                }
            }

            const communications = Array.from(deduped.values())
                .sort((a, b) => toTimestampMs(b.createdAt) - toTimestampMs(a.createdAt));

            return res.status(200).json({
                ...sanitizeData(profile),
                comunicazioni: communications
            });
        }

        const contentType = String(req.headers['content-type'] || '').toLowerCase();
        if (contentType && !contentType.includes('application/json')) {
            return res.status(415).json({ error: 'Content-Type non supportato. Usa application/json.' });
        }
        if (!isPlainObject(req.body)) {
            return res.status(400).json({ error: 'Corpo della richiesta non valido.' });
        }

        const type = cleanString(req.body.type, 100);
        const message = cleanString(req.body.message, 3000);
        if (!type || !message) {
            return res.status(400).json({ error: 'Tipo e messaggio della richiesta sono obbligatori.' });
        }

        await db.collection('richieste_supporto').add({
            userId: uid,
            tipo_richiesta: type,
            messaggio: message,
            dati_utente: {
                nome: cleanString(profile.nome, 200),
                cognome: cleanString(profile.cognome, 200),
                email: cleanString(profile.email, 254),
                url_sito: cleanUrl(profile.url_sito || profile.sito_web, 1000)
            },
            data: admin.firestore.FieldValue.serverTimestamp(),
            stato: 'Da gestire'
        });
        return res.status(200).json({ success: true });
    } catch (error) {
        const status = Number.isInteger(error?.status) ? error.status : 500;
        const responseBody = {
            error: status < 500 && error?.message ? error.message : 'Errore interno del server.'
        };
        if (status < 500 && typeof error?.code === 'string' && error.code) {
            responseBody.code = error.code;
        }
        return res.status(status).json(responseBody);
    }
};

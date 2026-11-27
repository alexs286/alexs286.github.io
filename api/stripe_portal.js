'use strict';
const crypto = require('crypto');
const {
    stripe,
    SITE_URL,
    setCors,
    rejectOrigin,
    requireCustomer,
    getOrCreateStripeCustomer
} = require('../lib/stripe');
const ALLOWED_METHODS = new Set(['POST']);
const MAX_BODY_BYTES = 16 * 1024;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 15;
const rateLimitStore = new Map();
function getClientKey(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = typeof forwarded === 'string' && forwarded.trim()
        ? forwarded.split(',')[0].trim()
        : (req.socket && req.socket.remoteAddress) || 'unknown';
    const authHeader = typeof req.headers.authorization === 'string'
        ? crypto.createHash('sha256').update(req.headers.authorization).digest('hex').slice(0, 16)
        : 'anon';
    return `${ip}:${authHeader}`;
}
function isRateLimited(key) {
    const now = Date.now();
    if (rateLimitStore.size > 5000) {
        for (const [k, entry] of rateLimitStore.entries()) {
            if (entry.resetAt <= now) rateLimitStore.delete(k);
        }
    }
    const existing = rateLimitStore.get(key);
    if (!existing || existing.resetAt <= now) {
        rateLimitStore.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
        return false;
    }
    existing.count += 1;
    return existing.count > RATE_LIMIT_MAX_REQUESTS;
}
function hasOversizedPayload(req) {
    const rawLength = req.headers['content-length'];
    if (rawLength !== undefined) {
        const parsed = Number(rawLength);
        if (!Number.isFinite(parsed) || parsed < 0 || parsed > MAX_BODY_BYTES) return true;
    }
    if (req.body !== undefined && req.body !== null) {
        try {
            const serialized = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
            if (Buffer.byteLength(serialized, 'utf8') > MAX_BODY_BYTES) return true;
        } catch {
            return true;
        }
    }
    return false;
}
function buildReturnUrl() {
    const base = new URL(SITE_URL);
    if (!['https:', 'http:'].includes(base.protocol)) {
        throw new Error('Invalid SITE_URL protocol');
    }
    return new URL('/dashboard.html', base.origin).toString();
}
function resolveSafeError(error) {
    const status = Number.isInteger(error && error.status) && error.status >= 400 && error.status < 600
        ? error.status
        : 500;
    if (status === 401) return { status, message: 'Autenticazione richiesta.' };
    if (status === 403) return { status, message: 'Accesso non autorizzato.' };
    if (status === 404) return { status, message: 'Risorsa non trovata.' };
    if (status === 429) return { status, message: 'Troppe richieste. Riprova tra poco.' };
    if (status >= 400 && status < 500 && error && typeof error.publicMessage === 'string') {
        return { status, message: error.publicMessage };
    }
    return {
        status: 500,
        message: 'Non è stato possibile aprire il portale Stripe. Verifica che il portale clienti sia abilitato nel tuo account Stripe.'
    };
}
module.exports = async function handler(req, res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    setCors(req, res);
    if (req.method === 'OPTIONS') return res.status(204).end();
    if (!ALLOWED_METHODS.has(req.method)) {
        res.setHeader('Allow', 'POST, OPTIONS');
        return res.status(405).json({ error: 'Metodo non consentito.' });
    }
    if (rejectOrigin(req)) {
        return res.status(403).json({ error: 'Origin non autorizzata.' });
    }
    if (hasOversizedPayload(req)) {
        return res.status(413).json({ error: 'Payload troppo grande.' });
    }
    if (isRateLimited(getClientKey(req))) {
        res.setHeader('Retry-After', String(Math.ceil(RATE_LIMIT_WINDOW_MS / 1000)));
        return res.status(429).json({ error: 'Troppe richieste. Riprova tra poco.' });
    }
    try {
        const authResult = await requireCustomer(req);
        if (!authResult || !authResult.uid) {
            return res.status(401).json({ error: 'Autenticazione richiesta.' });
        }
        const customer = await getOrCreateStripeCustomer(authResult.uid, authResult.profile);
        if (!customer || typeof customer.id !== 'string' || !/^cus_[A-Za-z0-9_]+$/.test(customer.id)) {
            return res.status(502).json({ error: 'Identificativo cliente Stripe non valido.' });
        }
        const returnUrl = buildReturnUrl();
        const idempotencyKey = crypto
            .createHash('sha256')
            .update(`${authResult.uid}:${customer.id}:${Math.floor(Date.now() / 10000)}`)
            .digest('hex');
        const session = await stripe.billingPortal.sessions.create(
            {
                customer: customer.id,
                return_url: returnUrl
            },
            { idempotencyKey }
        );
        if (!session || typeof session.url !== 'string') {
            return res.status(502).json({ error: 'Risposta non valida dal servizio Stripe.' });
        }
        const parsedSessionUrl = new URL(session.url);
        if (parsedSessionUrl.protocol !== 'https:') {
            return res.status(502).json({ error: 'URL del portale non sicuro.' });
        }
        return res.status(200).json({ success: true, url: parsedSessionUrl.toString() });
    } catch (error) {
        const safe = resolveSafeError(error);
        return res.status(safe.status).json({ error: safe.message });
    }
};

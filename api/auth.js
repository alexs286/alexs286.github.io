'use strict';

const admin = require('firebase-admin');
const crypto = require('node:crypto');

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://www.creatorweb.cc';
const RESET_TICKET_TTL_MS = 10 * 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_RATE_LIMIT_ENTRIES = 10_000;

const SENSITIVE_KEYS = new Set([
    'password',
    'passwordHash',
    'password_hash',
    'codici_sicurezza_hash',
    'recoveryCodes',
    'recovery_codes'
]);

const rateLimits = new Map();

function initFirebase() {
    if (admin.apps.length > 0) {
        return admin.firestore();
    }

    const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;
    if (!rawServiceAccount) {
        throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_WORK');
    }

    let serviceAccount;
    try {
        serviceAccount = typeof rawServiceAccount === 'string'
            ? JSON.parse(rawServiceAccount)
            : rawServiceAccount;
    } catch (_error) {
        throw new Error('FIREBASE_SERVICE_ACCOUNT_WORK non contiene un JSON valido');
    }

    if (!serviceAccount || typeof serviceAccount !== 'object' || !serviceAccount.project_id) {
        throw new Error('FIREBASE_SERVICE_ACCOUNT_WORK non ha una struttura valida');
    }

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });

    const db = admin.firestore();
    db.settings({ ignoreUndefinedProperties: true });
    return db;
}

const db = initFirebase();

function httpError(status, message) {
    const err = new Error(message);
    err.status = status;
    return err;
}

function setSecurityHeaders(req, res) {
    const origin = req.headers.origin;
    if (!origin || origin === ALLOWED_ORIGIN) {
        res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    }

    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
}

function sendJson(res, status, body) {
    return res.status(status).json(body);
}

function cleanString(value, maxLength = 500) {
    return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function getClientIp(req) {
    const vercelIp = req.headers['x-vercel-forwarded-for'];
    if (typeof vercelIp === 'string' && vercelIp.trim()) {
        return vercelIp.split(',')[0].trim();
    }

    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
        return forwarded.split(',')[0].trim();
    }

    return req.socket?.remoteAddress || 'unknown';
}

function pruneRateLimits(now) {
    if (rateLimits.size <= MAX_RATE_LIMIT_ENTRIES) return;
    for (const [key, entry] of rateLimits.entries()) {
        if (now - entry.startedAt >= RATE_LIMIT_WINDOW_MS) {
            rateLimits.delete(key);
        }
    }
    if (rateLimits.size > MAX_RATE_LIMIT_ENTRIES) {
        const overflow = rateLimits.size - MAX_RATE_LIMIT_ENTRIES;
        let removed = 0;
        for (const key of rateLimits.keys()) {
            rateLimits.delete(key);
            removed += 1;
            if (removed >= overflow) break;
        }
    }
}

function isRateLimited(req, bucket, limit) {
    const ip = getClientIp(req);
    const compositeKey = `${bucket}:${ip}`;
    const now = Date.now();

    const current = rateLimits.get(compositeKey);
    if (!current || now - current.startedAt >= RATE_LIMIT_WINDOW_MS) {
        rateLimits.set(compositeKey, { count: 1, startedAt: now });
        pruneRateLimits(now);
        return false;
    }

    current.count += 1;
    rateLimits.set(compositeKey, current);
    pruneRateLimits(now);
    return current.count > limit;
}

function sha256Hex(value) {
    return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

function hashesMatch(savedHash, candidateHash) {
    if (
        typeof savedHash !== 'string' ||
        typeof candidateHash !== 'string' ||
        !/^[a-f0-9]{64}$/i.test(savedHash) ||
        !/^[a-f0-9]{64}$/i.test(candidateHash)
    ) {
        return false;
    }

    const bufA = Buffer.from(savedHash.toLowerCase(), 'hex');
    const bufB = Buffer.from(candidateHash.toLowerCase(), 'hex');
    if (bufA.length !== bufB.length) return false;

    return crypto.timingSafeEqual(bufA, bufB);
}

function isValidPassword(value) {
    if (typeof value !== 'string') return false;
    if (value.length < 10 || value.length > 128) return false;
    if (value.trim().length < 10) return false;
    return true;
}

function isValidEmail(value) {
    if (typeof value !== 'string') return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function sanitizeProfile(value, seen = new WeakSet()) {
    if (value === null || value === undefined) return value;
    if (typeof value !== 'object') return value;

    if (typeof value.toDate === 'function') {
        try {
            return value.toDate().toISOString();
        } catch (_error) {
            return null;
        }
    }

    if (value instanceof Date) {
        return Number.isNaN(value.getTime()) ? null : value.toISOString();
    }

    if (seen.has(value)) return '[Circular]';
    seen.add(value);

    if (Array.isArray(value)) {
        return value.map(item => sanitizeProfile(item, seen));
    }

    const result = {};
    for (const [key, child] of Object.entries(value)) {
        if (SENSITIVE_KEYS.has(key)) continue;
        result[key] = sanitizeProfile(child, seen);
    }
    return result;
}

async function verifyCustomer(req) {
    const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
    const match = authHeader.match(/^Bearer\s+([A-Za-z0-9\-._~+/]+=*)$/);
    if (!match) {
        throw httpError(401, 'Autenticazione richiesta. Accedi nuovamente.');
    }

    const idToken = match[1];
    let decoded;
    try {
        decoded = await admin.auth().verifyIdToken(idToken, true);
    } catch (_error) {
        throw httpError(401, 'Sessione non valida o scaduta.');
    }

    if (!decoded?.uid) {
        throw httpError(401, 'Token di sessione non valido.');
    }

    const ref = db.collection('utenti_dashboard').doc(decoded.uid);
    const snapshot = await ref.get();
    if (!snapshot.exists) {
        throw httpError(404, 'Account non ancora collegato al profilo CreatorWeb. Contatta l’amministratore.');
    }

    return {
        decoded,
        ref,
        profile: snapshot.data() || {}
    };
}

async function redeemRecoveryCode(body) {
    const email = cleanString(body.email, 254).toLowerCase();
    const code = cleanString(body.code, 40).replace(/[\s-]/g, '').toUpperCase();

    if (!isValidEmail(email) || !/^[A-F0-9]{12}$/.test(code)) {
        return { ok: false };
    }

    let authUser;
    try {
        authUser = await admin.auth().getUserByEmail(email);
    } catch (_error) {
        return { ok: false };
    }

    if (!authUser || authUser.disabled) {
        return { ok: false };
    }

    const userRef = db.collection('utenti_dashboard').doc(authUser.uid);
    const ticketToken = crypto.randomBytes(32).toString('hex');
    const ticketRef = db.collection('password_reset_tickets').doc(sha256Hex(ticketToken));
    const codeHash = sha256Hex(code);
    const nowMs = Date.now();
    const expiresAt = admin.firestore.Timestamp.fromDate(new Date(nowMs + RESET_TICKET_TTL_MS));

    const accepted = await db.runTransaction(async transaction => {
        const [userSnapshot, ticketSnapshot] = await Promise.all([
            transaction.get(userRef),
            transaction.get(ticketRef)
        ]);

        if (!userSnapshot.exists || ticketSnapshot.exists) {
            return false;
        }

        const user = userSnapshot.data() || {};
        const savedHashes = Array.isArray(user.codici_sicurezza_hash)
            ? user.codici_sicurezza_hash
            : [];

        const matchIndex = savedHashes.findIndex(savedHash => hashesMatch(savedHash, codeHash));
        if (matchIndex < 0) {
            return false;
        }

        const remainingHashes = savedHashes.filter((_, idx) => idx !== matchIndex);

        transaction.update(userRef, {
            codici_sicurezza_hash: remainingHashes,
            codici_sicurezza_usati: admin.firestore.FieldValue.increment(1),
            ultimo_uso_codice_sicurezza: admin.firestore.FieldValue.serverTimestamp()
        });

        transaction.create(ticketRef, {
            uid: authUser.uid,
            status: 'pending',
            created_at: admin.firestore.FieldValue.serverTimestamp(),
            expires_at: expiresAt
        });

        return true;
    });

    return accepted
        ? { ok: true, resetToken: ticketToken }
        : { ok: false };
}

async function completePasswordReset(body) {
    const resetToken = cleanString(body.resetToken, 128).toLowerCase();
    const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';

    if (!/^[a-f0-9]{64}$/.test(resetToken) || !isValidPassword(newPassword)) {
        throw httpError(
            400,
            'Codice di recupero o nuova password non validi. La password deve contenere tra 10 e 128 caratteri.'
        );
    }

    const ticketRef = db.collection('password_reset_tickets').doc(sha256Hex(resetToken));
    const requestId = crypto.randomBytes(16).toString('hex');
    let uid = null;

    const claimed = await db.runTransaction(async transaction => {
        const snapshot = await transaction.get(ticketRef);
        if (!snapshot.exists) return false;

        const ticket = snapshot.data() || {};
        const expiresAtDate = ticket.expires_at?.toDate?.();
        if (
            ticket.status !== 'pending' ||
            typeof ticket.uid !== 'string' ||
            !ticket.uid ||
            !expiresAtDate ||
            expiresAtDate.getTime() <= Date.now()
        ) {
            return false;
        }

        uid = ticket.uid;
        transaction.update(ticketRef, {
            status: 'processing',
            request_id: requestId,
            processing_at: admin.firestore.FieldValue.serverTimestamp()
        });
        return true;
    });

    if (!claimed || !uid) {
        throw httpError(401, 'Codice di recupero non valido o scaduto. Richiedi una nuova verifica.');
    }

    try {
        const targetUser = await admin.auth().getUser(uid);
        if (targetUser.disabled) {
            throw httpError(403, 'Account disabilitato. Contatta l’amministratore.');
        }

        await admin.auth().updateUser(uid, { password: newPassword });

        const userRef = db.collection('utenti_dashboard').doc(uid);
        await db.runTransaction(async transaction => {
            const [ticketSnapshot, userSnapshot] = await Promise.all([
                transaction.get(ticketRef),
                transaction.get(userRef)
            ]);

            const ticket = ticketSnapshot.data() || {};
            if (
                !ticketSnapshot.exists ||
                ticket.status !== 'processing' ||
                ticket.request_id !== requestId
            ) {
                throw httpError(409, 'Reset ticket non più valido.');
            }

            if (!userSnapshot.exists) {
                throw httpError(404, 'Profilo utente non trovato.');
            }

            transaction.update(userSnapshot.ref, {
                'account.must_change_password': false,
                'account.password_changed_at': admin.firestore.FieldValue.serverTimestamp(),
                'account.password_reset_at': admin.firestore.FieldValue.serverTimestamp()
            });
            transaction.delete(ticketRef);
        });

        await admin.auth().revokeRefreshTokens(uid).catch(err => {
            console.warn('Impossibile revocare le sessioni precedenti:', err.message);
        });

        return { success: true };
    } catch (error) {
        await db.runTransaction(async transaction => {
            const snapshot = await transaction.get(ticketRef);
            const ticket = snapshot.data() || {};
            if (
                snapshot.exists &&
                ticket.status === 'processing' &&
                ticket.request_id === requestId
            ) {
                transaction.update(ticketRef, {
                    status: 'pending',
                    request_id: admin.firestore.FieldValue.delete(),
                    processing_at: admin.firestore.FieldValue.delete()
                });
            }
        }).catch(() => {});

        console.error('Password reset failed:', error.code || error.message);
        throw httpError(500, 'Si è verificato un errore durante il reset della password.');
    }
}

function parseJsonBody(req) {
    if (!req.body) return {};
    if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
        return req.body;
    }
    if (typeof req.body === 'string' || Buffer.isBuffer(req.body)) {
        try {
            const parsed = JSON.parse(req.body.toString('utf8'));
            return parsed && typeof parsed === 'object' ? parsed : {};
        } catch (_error) {
            throw httpError(400, 'Corpo della richiesta JSON non valido.');
        }
    }
    return {};
}

module.exports = async function handler(req, res) {
    setSecurityHeaders(req, res);

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    if (req.headers.origin && req.headers.origin !== ALLOWED_ORIGIN) {
        return sendJson(res, 403, { error: 'Origin non autorizzata.' });
    }

    if (req.method !== 'POST') {
        return sendJson(res, 405, { error: 'Metodo non consentito.' });
    }

    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    if (contentType && !contentType.includes('application/json')) {
        return sendJson(res, 415, { error: 'Content-Type non supportato. Usa application/json.' });
    }

    if (isRateLimited(req, 'global', 30)) {
        return sendJson(res, 429, { error: 'Troppe richieste. Riprova tra un minuto.' });
    }

    try {
        const body = parseJsonBody(req);
        const action = cleanString(body.action, 60);

        if (action === 'redeem_recovery_code') {
            if (isRateLimited(req, 'redeem_recovery_code', 8)) {
                return sendJson(res, 429, { error: 'Troppi tentativi di recupero. Riprova tra un minuto.' });
            }
            const result = await redeemRecoveryCode(body);
            if (!result.ok) {
                return sendJson(res, 401, { error: 'Email o codice non validi.' });
            }
            return sendJson(res, 200, { success: true, resetToken: result.resetToken });
        }

        if (action === 'complete_password_reset') {
            if (isRateLimited(req, 'complete_password_reset', 10)) {
                return sendJson(res, 429, { error: 'Troppi tentativi di reset. Riprova tra un minuto.' });
            }
            const result = await completePasswordReset(body);
            return sendJson(res, 200, result);
        }

        const { decoded, ref, profile } = await verifyCustomer(req);

        if (action === 'profile') {
            return sendJson(res, 200, {
                success: true,
                uid: decoded.uid,
                email: decoded.email || profile.email || null,
                must_change_password: profile.account?.must_change_password === true,
                data: sanitizeProfile(profile)
            });
        }

        if (action === 'change_password') {
            if (isRateLimited(req, 'change_password', 10)) {
                return sendJson(res, 429, { error: 'Troppi tentativi di cambio password. Riprova tra un minuto.' });
            }

            const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
            if (!isValidPassword(newPassword)) {
                return sendJson(res, 400, {
                    error: 'La nuova password deve contenere tra 10 e 128 caratteri.'
                });
            }

            await admin.auth().updateUser(decoded.uid, { password: newPassword });

            await ref.set({
                account: {
                    must_change_password: false,
                    password_changed_at: admin.firestore.FieldValue.serverTimestamp()
                }
            }, { merge: true });

            await admin.auth().revokeRefreshTokens(decoded.uid).catch(err => {
                console.warn('Impossibile revocare le sessioni precedenti:', err.message);
            });

            return sendJson(res, 200, { success: true });
        }

        return sendJson(res, 400, { error: 'Azione non riconosciuta.' });
    } catch (error) {
        if (!error.status) {
            console.error('Auth API error:', error);
        }
        return sendJson(res, error.status || 500, {
            error: error.status ? error.message : 'Errore interno del server.'
        });
    }
};

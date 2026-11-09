const admin = require('firebase-admin');
const crypto = require('node:crypto');

const ALLOWED_ORIGIN = 'https://www.creatorweb.cc';
const RESET_TICKET_TTL_MS = 10 * 60 * 1000;
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

function setCors(req, res) {
    const origin = req.headers.origin;
    if (!origin || origin === ALLOWED_ORIGIN) {
        res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    }
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'no-store, max-age=0');
}

function sendJson(res, status, body) {
    return res.status(status).json(body);
}

function cleanString(value, maxLength = 500) {
    return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function rateLimited(req, limit = 30) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = (typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : '')
        || req.socket?.remoteAddress
        || 'unknown';
    const now = Date.now();
    const current = rateLimits.get(ip) || { count: 0, startedAt: now };
    if (now - current.startedAt >= 60000) {
        current.count = 0;
        current.startedAt = now;
    }
    current.count += 1;
    rateLimits.set(ip, current);
    if (rateLimits.size > 5000) {
        for (const [key, value] of rateLimits) {
            if (now - value.startedAt >= 60000) rateLimits.delete(key);
        }
    }
    return current.count > limit;
}

function hash(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

function hashesMatch(savedHash, candidateHash) {
    if (typeof savedHash !== 'string' || !/^[a-f0-9]{64}$/i.test(savedHash)) return false;
    return crypto.timingSafeEqual(
        Buffer.from(savedHash, 'hex'),
        Buffer.from(candidateHash, 'hex')
    );
}

function validPassword(value) {
    return typeof value === 'string' && value.length >= 10 && value.length <= 128;
}

function sanitizeProfile(value) {
    if (Array.isArray(value)) return value.map(sanitizeProfile);
    if (!value || typeof value !== 'object') return value;
    if (typeof value.toDate === 'function') return value.toDate().toISOString();
    const result = {};
    for (const [key, child] of Object.entries(value)) {
        if (['password', 'passwordHash', 'codici_sicurezza_hash'].includes(key)) continue;
        result[key] = sanitizeProfile(child);
    }
    return result;
}

async function verifyCustomer(req) {
    const header = req.headers.authorization || '';
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) {
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

    const ref = db.collection('utenti_dashboard').doc(decoded.uid);
    const snapshot = await ref.get();
    if (!snapshot.exists) {
        const error = new Error('Account non ancora collegato al profilo CreatorWeb. Contatta l’amministratore.');
        error.status = 404;
        throw error;
    }
    return { decoded, ref, profile: snapshot.data() || {} };
}

async function redeemRecoveryCode(body) {
    const email = cleanString(body.email, 254).toLowerCase();
    const code = cleanString(body.code, 30).replace(/[\s-]/g, '').toUpperCase();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^[A-F0-9]{12}$/.test(code)) {
        return { ok: false };
    }

    let authUser;
    try {
        authUser = await admin.auth().getUserByEmail(email);
    } catch (_error) {
        return { ok: false };
    }
    if (authUser.disabled) return { ok: false };

    const userRef = db.collection('utenti_dashboard').doc(authUser.uid);
    const ticketToken = crypto.randomBytes(32).toString('hex');
    const ticketRef = db.collection('password_reset_tickets').doc(hash(ticketToken));
    const codeHash = hash(code);
    const expiresAt = admin.firestore.Timestamp.fromDate(new Date(Date.now() + RESET_TICKET_TTL_MS));

    const accepted = await db.runTransaction(async transaction => {
        const [userSnapshot, ticketSnapshot] = await Promise.all([
            transaction.get(userRef),
            transaction.get(ticketRef)
        ]);
        if (!userSnapshot.exists || ticketSnapshot.exists) return false;

        const user = userSnapshot.data() || {};
        const savedHashes = Array.isArray(user.codici_sicurezza_hash)
            ? user.codici_sicurezza_hash
            : [];
        const index = savedHashes.findIndex(savedHash => hashesMatch(savedHash, codeHash));
        if (index < 0) return false;

        const remainingHashes = [...savedHashes];
        remainingHashes.splice(index, 1);
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

    return accepted ? { ok: true, resetToken: ticketToken } : { ok: false };
}

async function completePasswordReset(body) {
    const resetToken = cleanString(body.resetToken, 128);
    const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
    if (!/^[a-f0-9]{64}$/i.test(resetToken) || !validPassword(newPassword)) {
        const error = new Error('Codice di recupero o nuova password non validi. La password deve contenere almeno 10 caratteri.');
        error.status = 400;
        throw error;
    }

    const ticketRef = db.collection('password_reset_tickets').doc(hash(resetToken));
    const requestId = crypto.randomBytes(16).toString('hex');
    let uid = null;

    const claimed = await db.runTransaction(async transaction => {
        const snapshot = await transaction.get(ticketRef);
        if (!snapshot.exists) return false;
        const ticket = snapshot.data() || {};
        const expiresAt = ticket.expires_at?.toDate?.();
        if (ticket.status !== 'pending' || !expiresAt || expiresAt.getTime() <= Date.now()) return false;
        uid = ticket.uid;
        transaction.update(ticketRef, {
            status: 'processing',
            request_id: requestId,
            processing_at: admin.firestore.FieldValue.serverTimestamp()
        });
        return true;
    });

    if (!claimed || !uid) {
        const error = new Error('Codice di recupero non valido o scaduto. Richiedi una nuova verifica.');
        error.status = 401;
        throw error;
    }

    try {
        await admin.auth().updateUser(uid, { password: newPassword });

        await db.runTransaction(async transaction => {
            const [ticketSnapshot, userSnapshot] = await Promise.all([
                transaction.get(ticketRef),
                transaction.get(db.collection('utenti_dashboard').doc(uid))
            ]);
            const ticket = ticketSnapshot.data() || {};
            if (!ticketSnapshot.exists || ticket.status !== 'processing' || ticket.request_id !== requestId) {
                throw new Error('Reset ticket non più valido');
            }
            if (!userSnapshot.exists) throw new Error('Profilo utente non trovato');

            transaction.update(userSnapshot.ref, {
                'account.must_change_password': false,
                'account.password_changed_at': admin.firestore.FieldValue.serverTimestamp(),
                'account.password_reset_at': admin.firestore.FieldValue.serverTimestamp()
            });
            transaction.delete(ticketRef);
        });

        await admin.auth().revokeRefreshTokens(uid).catch(error => {
            console.warn('Impossibile revocare le sessioni precedenti:', error.message);
        });
        return { success: true };
    } catch (error) {
        await db.runTransaction(async transaction => {
            const snapshot = await transaction.get(ticketRef);
            const ticket = snapshot.data() || {};
            if (snapshot.exists && ticket.status === 'processing' && ticket.request_id === requestId) {
                transaction.update(ticketRef, { status: 'pending', request_id: admin.firestore.FieldValue.delete() });
            }
        }).catch(() => {});
        throw error;
    }
}

module.exports = async function handler(req, res) {
    setCors(req, res);
    if (req.method === 'OPTIONS') return res.status(204).end();
    if (req.headers.origin && req.headers.origin !== ALLOWED_ORIGIN) {
        return sendJson(res, 403, { error: 'Origin non autorizzata' });
    }
    if (req.method !== 'POST') return sendJson(res, 405, { error: 'Metodo non consentito' });
    if (rateLimited(req, 25)) return sendJson(res, 429, { error: 'Troppe richieste. Riprova tra un minuto.' });

    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const action = cleanString(body.action, 60);

    try {
        if (action === 'redeem_recovery_code') {
            const result = await redeemRecoveryCode(body);
            if (!result.ok) return sendJson(res, 401, { error: 'Email o codice non validi.' });
            return sendJson(res, 200, { success: true, resetToken: result.resetToken });
        }

        if (action === 'complete_password_reset') {
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
            const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
            if (!validPassword(newPassword)) {
                return sendJson(res, 400, { error: 'La nuova password deve contenere almeno 10 caratteri.' });
            }
            await admin.auth().updateUser(decoded.uid, { password: newPassword });
            await ref.set({
                account: {
                    must_change_password: false,
                    password_changed_at: admin.firestore.FieldValue.serverTimestamp()
                }
            }, { merge: true });
            return sendJson(res, 200, { success: true });
        }

        return sendJson(res, 400, { error: 'Azione non riconosciuta.' });
    } catch (error) {
        if (!error.status) console.error('Auth API error:', error);
        return sendJson(res, error.status || 500, {
            error: error.status ? error.message : 'Errore interno del server.'
        });
    }
};

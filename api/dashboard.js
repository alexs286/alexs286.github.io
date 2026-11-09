const admin = require('firebase-admin');

const ALLOWED_ORIGIN = 'https://www.creatorweb.cc';
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
    if (!origin || origin === ALLOWED_ORIGIN) res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'no-store, max-age=0');
}

function rateLimited(req) {
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
    return current.count > 60;
}

async function requireCustomer(req) {
    const match = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
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

    const userRef = db.collection('utenti_dashboard').doc(decoded.uid);
    const snapshot = await userRef.get();
    if (!snapshot.exists) {
        const error = new Error('Profilo non trovato. Contatta l’amministratore.');
        error.status = 404;
        throw error;
    }
    const profile = snapshot.data() || {};
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
    return value.trim().replace(/[<>]/g, '').slice(0, maxLength);
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

module.exports = async function handler(req, res) {
    setCors(req, res);
    if (req.method === 'OPTIONS') return res.status(204).end();
    if (req.headers.origin && req.headers.origin !== ALLOWED_ORIGIN) {
        return res.status(403).json({ error: 'Origin non autorizzata' });
    }
    if (!['GET', 'POST'].includes(req.method)) {
        return res.status(405).json({ error: 'Metodo non consentito' });
    }
    if (rateLimited(req)) return res.status(429).json({ error: 'Troppe richieste. Riprova più tardi.' });

    try {
        const { uid, profile } = await requireCustomer(req);

        if (req.method === 'GET') {
            return res.status(200).json(sanitizeProfile(profile));
        }

        const body = req.body && typeof req.body === 'object' ? req.body : {};
        const type = cleanString(body.type, 100);
        const message = cleanString(body.message, 3000);
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
                url_sito: cleanString(profile.url_sito || profile.sito_web, 1000)
            },
            data: admin.firestore.FieldValue.serverTimestamp(),
            stato: 'Da gestire'
        });
        return res.status(200).json({ success: true });
    } catch (error) {
        if (!error.status) console.error('Dashboard API error:', error);
        return res.status(error.status || 500).json({
            error: error.status ? error.message : 'Errore interno del server.',
            code: error.code || undefined
        });
    }
};

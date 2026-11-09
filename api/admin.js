const admin = require('firebase-admin');
const crypto = require('crypto');

if (!admin.apps.length) {
    const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;

    if (!rawServiceAccount) {
        throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_WORK');
    }

    let serviceAccount;
    try {
        serviceAccount = typeof rawServiceAccount === 'string'
            ? JSON.parse(rawServiceAccount)
            : rawServiceAccount;
    } catch (error) {
        throw new Error('FIREBASE_SERVICE_ACCOUNT_WORK non contiene un JSON valido');
    }

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();
const rateLimits = new Map();

const ALLOWED_ORIGIN = 'https://www.creatorweb.cc';
const ALLOWED_COLLECTIONS = new Set([
    'richieste_preventivo',
    'utenti_dashboard',
    'richieste_supporto',
    'stato del servizio'
]);

const USER_FIELDS = new Set([
    'email',
    'password',
    'nome',
    'nome_utente',
    'cognome',
    'ruolo',
    'stato_sito',
    'stato_progetto',
    'telefono',
    'url_sito',
    'sito_web',
    'sito',
    'tipo_servizio',
    'budget',
    'budget_ref',
    'scadenza_dominio',
    'stato_pagamento',
    'totale_pagamento',
    'importo_totale',
    'metodo_pagamento',
    'note_pagamento',
    'costo_rata'
]);

const STATUS_VALUES = new Set([
    'pieno',
    'problemi tecnici',
    'errori di terzi',
    'servizio in pausa per festività',
    'manutenzione'
]);

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

function checkRateLimit(req) {
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

    current.count++;
    rateLimits.set(ip, current);

    if (rateLimits.size > 5000) {
        for (const [key, value] of rateLimits) {
            if (now - value.startedAt >= 60000) rateLimits.delete(key);
        }
    }

    return current.count > 100;
}

function cleanString(value, maxLength = 5000) {
    if (typeof value !== 'string') return '';
    return value.trim().slice(0, maxLength);
}

function validDocumentId(value) {
    return typeof value === 'string'
        && value.trim().length > 0
        && value.trim().length <= 150
        && !value.includes('/')
        && value.trim() === value;
}

function isValidDateOnly(value) {
    if (value === '') return true;
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;

    const [year, month, day] = value.split('-').map(Number);
    const date = new Date(Date.UTC(year, month - 1, day));
    return date.getUTCFullYear() === year
        && date.getUTCMonth() === month - 1
        && date.getUTCDate() === day;
}

function serializeData(value) {
    if (value === null || value === undefined) return value;
    if (typeof value.toDate === 'function') return value.toDate().toISOString();
    if (value instanceof Date) return value.toISOString();
    if (Array.isArray(value)) return value.map(serializeData);
    if (typeof value === 'object') {
        const result = {};
        for (const [key, child] of Object.entries(value)) {
            result[key] = serializeData(child);
        }
        return result;
    }
    return value;
}

async function verifyAdmin(req) {
    const header = req.headers.authorization || '';
    const match = header.match(/^Bearer\s+(.+)$/i);

    if (!match) {
        const error = new Error('Autenticazione richiesta. Effettua nuovamente l’accesso.');
        error.status = 401;
        throw error;
    }

    const allowedUids = (process.env.ADMIN_UIDS || '')
        .split(',')
        .map(uid => uid.trim())
        .filter(Boolean);

    if (allowedUids.length === 0) {
        const error = new Error('Configurazione amministratore mancante sul server.');
        error.status = 503;
        throw error;
    }

    let decoded;
    try {
        decoded = await admin.auth().verifyIdToken(match[1]);
    } catch (_error) {
        const error = new Error('Sessione non valida o scaduta.');
        error.status = 401;
        throw error;
    }

    if (!allowedUids.includes(decoded.uid)) {
        const error = new Error('Non hai i permessi per accedere al pannello amministrativo.');
        error.status = 403;
        throw error;
    }

    return decoded;
}

function pickUserFields(source, creating = false) {
    const result = {};
    if (!source || typeof source !== 'object' || Array.isArray(source)) return result;

    for (const [key, value] of Object.entries(source)) {
        if (!USER_FIELDS.has(key)) continue;
        if (typeof value === 'string') {
            result[key] = cleanString(value, key === 'password' ? 200 : 2000);
        } else if (value === null && !creating) {
            result[key] = null;
        }
    }

    if (typeof result.email === 'string') {
        result.email = result.email.toLowerCase();
    }

    if (typeof result.nome_utente === 'string') {
        result.nome_utente = result.nome_utente.toLowerCase();
    }


    if (Object.prototype.hasOwnProperty.call(result, 'scadenza_dominio')
        && !isValidDateOnly(result.scadenza_dominio)) {
        throw Object.assign(new Error('La scadenza del dominio deve essere una data valida (AAAA-MM-GG).'), { status: 400 });
    }

    return result;
}

module.exports = async function handler(req, res) {
    setCors(req, res);

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    if (req.headers.origin && req.headers.origin !== ALLOWED_ORIGIN) {
        return sendJson(res, 403, { error: 'Origin non autorizzata' });
    }

    if (req.method !== 'POST') {
        return sendJson(res, 405, { error: 'Metodo non consentito' });
    }

    if (checkRateLimit(req)) {
        return sendJson(res, 429, { error: 'Troppe richieste. Riprova tra un minuto.' });
    }

    try {
        await verifyAdmin(req);

        const body = req.body && typeof req.body === 'object' ? req.body : {};
        const action = cleanString(body.action, 80);

        if (action === 'get_collection') {
            const collectionName = cleanString(body.collection, 100);

            if (!ALLOWED_COLLECTIONS.has(collectionName)) {
                return sendJson(res, 403, { error: 'Collezione non autorizzata' });
            }

            const snapshot = await db.collection(collectionName).get();
            const docs = snapshot.docs.map(doc => ({
                id: doc.id,
                data: serializeData(doc.data())
            }));

            docs.sort((a, b) => {
                const dateA = a.data.data || a.data.createdAt || a.data.ultimo_aggiornamento || '';
                const dateB = b.data.data || b.data.createdAt || b.data.ultimo_aggiornamento || '';
                return String(dateB).localeCompare(String(dateA));
            });

            return sendJson(res, 200, { data: docs });
        }

        if (action === 'get_status') {
            const doc = await db.collection('stato del servizio').doc('current_status').get();
            return sendJson(res, 200, {
                data: doc.exists ? serializeData(doc.data()) : null
            });
        }

        if (action === 'create_user') {
            const collectionName = cleanString(
                body.collection || 'utenti_dashboard',
                100
            );

            if (collectionName !== 'utenti_dashboard') {
                return sendJson(res, 403, {
                    error: 'Collezione non autorizzata'
                });
            }

            const userData = pickUserFields(body.data, true);

            const recoveryCodes = Array.isArray(body.recoveryCodes)
                ? body.recoveryCodes.map(code =>
                    cleanString(code, 30)
                        .replace(/[\s-]/g, '')
                        .toUpperCase()
                )
                : [];

            if (
                !userData.email ||
                !userData.password ||
                !userData.nome_utente
            ) {
                return sendJson(res, 400, {
                    error: 'Email, password e nome utente sono obbligatori'
                });
            }

            if (
                recoveryCodes.length !== 8 ||
                new Set(recoveryCodes).size !== 8 ||
                recoveryCodes.some(code => !/^[A-F0-9]{12}$/.test(code))
            ) {
                return sendJson(res, 400, {
                    error: 'Devi generare esattamente 8 codici validi e distinti'
                });
            }

            userData.nome = userData.nome || userData.nome_utente;

            const emailExists = await db
                .collection('utenti_dashboard')
                .where('email', '==', userData.email)
                .limit(1)
                .get();

            if (!emailExists.empty) {
                return sendJson(res, 409, {
                    error: 'Questa email è già associata a un utente'
                });
            }

            const usernameExists = await db
                .collection('utenti_dashboard')
                .where('nome_utente', '==', userData.nome_utente)
                .limit(1)
                .get();

            if (!usernameExists.empty) {
                return sendJson(res, 409, {
                    error: 'Questo nome utente è già utilizzato'
                });
            }

            userData.codici_sicurezza_hash = recoveryCodes.map(code =>
                crypto.createHash('sha256').update(code).digest('hex')
            );

            userData.codici_sicurezza_generati_il =
                admin.firestore.FieldValue.serverTimestamp();

            userData.data = admin.firestore.FieldValue.serverTimestamp();

            const userRef = await db
                .collection('utenti_dashboard')
                .add(userData);

            return sendJson(res, 200, {
                success: true,
                id: userRef.id,
                recovery_codes_saved: 8
            });
        }


        if (action === 'update_user') {
            const collectionName = cleanString(body.collection || 'utenti_dashboard', 100);
            const userId = body.userId;

            if (collectionName !== 'utenti_dashboard') {
                return sendJson(res, 403, { error: 'Collezione non autorizzata' });
            }
            if (!validDocumentId(userId)) {
                return sendJson(res, 400, { error: 'ID utente non valido' });
            }

            const cleanData = pickUserFields(body.data, false);
            if (Object.keys(cleanData).length === 0) {
                return sendJson(res, 400, { error: 'Nessun campo utente valido da aggiornare' });
            }

            cleanData.ultimo_aggiornamento = admin.firestore.FieldValue.serverTimestamp();
            await db.collection('utenti_dashboard').doc(userId).set(cleanData, { merge: true });
            return sendJson(res, 200, { success: true });
        }

        if (action === 'update_cloudflare_config') {
            const userId = body.userId;
            const data = body.data && typeof body.data === 'object' ? body.data : {};

            if (!validDocumentId(userId)) {
                return sendJson(res, 400, { error: 'ID utente non valido' });
            }

            const apiToken = cleanString(
                data.api_token || data.apitoken_cf || '',
                1000
            );

            const accountId = cleanString(
                data.account_id || data.accid_cf || '',
                200
            );

            const zoneId = cleanString(
                data.zone_id || '',
                200
            );
            const hasChanges = Boolean(
                apiToken || accountId || zoneId ||
                data.clear_apitoken_cf === true ||
                data.clear_accid_cf === true ||
                data.clear_zone_id === true
            );

            if (!hasChanges) {
                return sendJson(res, 400, { error: 'Nessuna modifica Cloudflare da salvare' });
            }

            const userRef = db.collection('users').doc(userId);
            const snap = await userRef.get();
            const existing = snap.exists ? (snap.data() || {}) : {};
            const cloudflare = { ...(existing.cloudflare || {}) };

            if (!cloudflare.api_token && existing.apitoken_cf) cloudflare.api_token = existing.apitoken_cf;
            if (!cloudflare.account_id && existing.accid_cf) cloudflare.account_id = existing.accid_cf;
            if (!cloudflare.zone_id && existing.zone_id) cloudflare.zone_id = existing.zone_id;

            if (data.clear_apitoken_cf === true) delete cloudflare.api_token;
            else if (apiToken) cloudflare.api_token = apiToken;

            if (data.clear_accid_cf === true) delete cloudflare.account_id;
            else if (accountId) cloudflare.account_id = accountId;

            if (data.clear_zone_id === true) delete cloudflare.zone_id;
            else if (zoneId) cloudflare.zone_id = zoneId;

            await userRef.set({ cloudflare }, { merge: true });
            const savedSnapshot = await userRef.get();
            
            const savedCloudflare = savedSnapshot.exists
                ? savedSnapshot.data().cloudflare || {}
                : {};
            
            const missingFields = [
                'api_token',
                'account_id',
                'zone_id'
            ].filter(field => !savedCloudflare[field]);
            
            return sendJson(res, 200, {
                success: true,
                config_complete: missingFields.length === 0,
                missing_fields: missingFields
            });
            
            return sendJson(res, 200, { success: true });
        }

        if (action === 'delete_support_request') {
            const requestId = body.requestId;
            if (!validDocumentId(requestId)) {
                return sendJson(res, 400, { error: 'ID richiesta non valido' });
            }

            const ref = db.collection('richieste_supporto').doc(requestId);
            const snapshot = await ref.get();
            if (!snapshot.exists) {
                return sendJson(res, 404, { error: 'Richiesta non trovata' });
            }

            await ref.delete();
            return sendJson(res, 200, { success: true, message: 'Richiesta eliminata' });
        }

        if (action === 'update_status') {
            const stato = cleanString(body.stato, 100).toLowerCase();
            if (!STATUS_VALUES.has(stato)) {
                return sendJson(res, 400, { error: 'Stato del servizio non valido' });
            }

            const updatePayload = {
                stato,
                status: stato,
                ultimo_aggiornamento: admin.firestore.FieldValue.serverTimestamp()
            };

            if (body.messaggio !== undefined) {
                updatePayload.messaggio = cleanString(body.messaggio, 3000);
            }
            if (body.link_responsabilita !== undefined) {
                const link = cleanString(body.link_responsabilita, 2000);
                if (link && !/^https:\/\//i.test(link)) {
                    return sendJson(res, 400, { error: 'Il link deve iniziare con https://' });
                }
                updatePayload.link_responsabilita = link || null;
            }

            await db.collection('stato del servizio').doc('current_status').set(updatePayload, { merge: true });
            return sendJson(res, 200, { success: true });
        }

        return sendJson(res, 400, { error: 'Azione non riconosciuta' });

    } catch (error) {
        console.error('Admin API error:', error);
        return sendJson(res, error.status || 500, {
            error: error.status ? error.message : 'Errore interno del server'
        });
    }
};

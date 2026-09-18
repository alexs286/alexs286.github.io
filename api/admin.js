const admin = require('firebase-admin');

if (!admin.apps.length) {
    try {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_WORK);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
    } catch (e) {
        console.error(e);
    }
}

const db = admin.firestore();
const rateLimits = new Map();

const sanitize = (input) => {
    if (typeof input !== 'string') return input;
    return input.trim().replace(/[<>]/g, '');
};

const serializeData = (data) => {
    if (!data || typeof data !== 'object') return data;
    if (typeof data.toDate === 'function') return data.toDate().toISOString();
    if (data._seconds !== undefined) return new Date(data._seconds * 1000).toISOString();
    const res = Array.isArray(data) ? [] : {};
    for (const [key, val] of Object.entries(data)) {
        res[key] = serializeData(val);
    }
    return res;
};

const checkRateLimit = (ip) => {
    const now = Date.now();
    const limit = rateLimits.get(ip) || { count: 0, time: now };
    if (now - limit.time > 60000) {
        limit.count = 1;
        limit.time = now;
    } else {
        limit.count++;
    }
    rateLimits.set(ip, limit);
    return limit.count > 60;
};

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (checkRateLimit(clientIp)) {
        return res.status(429).json({ error: 'Rate limit superato. Riprova tra un minuto.' });
    }

    try {
        const body = req.body || {};
        const action = body.action || req.query.action;

        if (action === 'get_collection') {
            const collectionName = sanitize(body.collection || req.query.collection);
            if (!collectionName) return res.status(400).json({ error: 'Collezione mancante' });

            const snapshot = await db.collection(collectionName).get();
            const docs = [];
            snapshot.forEach(doc => {
                docs.push({ id: doc.id, data: serializeData(doc.data()) });
            });

            docs.sort((a, b) => {
                const dateA = a.data.data || a.data.createdAt || a.data.ultimo_aggiornamento || '';
                const dateB = b.data.data || b.data.createdAt || b.data.ultimo_aggiornamento || '';
                if (dateA && dateB) return String(dateB).localeCompare(String(dateA));
                return 0;
            });

            return res.status(200).json({ data: docs });
        }

        if (action === 'get_status') {
            const doc = await db.collection('stato del servizio').doc('current_status').get();
            if (!doc.exists) {
                return res.status(200).json({ data: null });
            }
            return res.status(200).json({ data: serializeData(doc.data()) });
        }

        if (action === 'create_user') {
            const collectionName = sanitize(body.collection || 'utenti_dashboard');
            const { email, password, nome, ruolo } = body.data || {};

            if (!email || !password) return res.status(400).json({ error: 'Email e password obbligatorie' });

            const userRef = await db.collection(collectionName).add({
                email: sanitize(email),
                password: sanitize(password),
                nome: sanitize(nome || ''),
                ruolo: sanitize(ruolo || 'cliente'),
                data: admin.firestore.FieldValue.serverTimestamp()
            });

            return res.status(200).json({ success: true, id: userRef.id });
        }

        if (action === 'update_status') {
            const collectionName = sanitize(body.collection || 'stato del servizio');
            const docId = sanitize(body.docId || 'current_status');
            const stato = sanitize(body.stato || '');
            const messaggio = body.messaggio ? sanitize(body.messaggio) : null;
            const link = body.link_responsabilita ? sanitize(body.link_responsabilita) : null;

            if (!stato) return res.status(400).json({ error: 'Stato mancante' });

            const updatePayload = {
                stato: stato,
                status: stato,
                ultimo_aggiornamento: admin.firestore.FieldValue.serverTimestamp()
            };
            if (link !== null) updatePayload.link_responsabilita = link;
            if (messaggio !== null) updatePayload.messaggio = messaggio;

            await db.collection(collectionName).doc(docId).set(updatePayload, { merge: true });

            return res.status(200).json({ success: true });
        }

        return res.status(400).json({ error: 'Azione non riconosciuta' });

    } catch (error) {
        console.error('API Error:', error);
        return res.status(500).json({ error: 'Errore interno del server' });
    }
}

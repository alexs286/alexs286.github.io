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
    return limit.count > 50;
};

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (checkRateLimit(clientIp)) {
        return res.status(429).json({ error: 'Rate limit superato' });
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Metodo non consentito' });
    }

    try {
        const body = req.body;
        const action = body.action;

        if (action === 'get_collection') {
            const collectionName = sanitize(body.collection);
            if (!collectionName) return res.status(400).json({ error: 'Collezione mancante' });

            const snapshot = await db.collection(collectionName).orderBy('data', 'desc').limit(100).get().catch(async () => {
                return await db.collection(collectionName).limit(100).get();
            });

            const docs = [];
            snapshot.forEach(doc => docs.push({ id: doc.id, data: doc.data() }));
            return res.status(200).json({ data: docs });
        }

        if (action === 'create_user') {
            const collectionName = sanitize(body.collection);
            const { email, password, nome, ruolo } = body.data;

            if (!email || !password) return res.status(400).json({ error: 'Email e password obbligatorie' });

            const userRef = await db.collection(collectionName).add({
                email: sanitize(email),
                password: sanitize(password), 
                nome: sanitize(nome),
                ruolo: sanitize(ruolo),
                data: admin.firestore.FieldValue.serverTimestamp()
            });

            return res.status(200).json({ success: true, id: userRef.id });
        }

        if (action === 'update_status') {
            const collectionName = sanitize(body.collection);
            const docId = sanitize(body.docId);
            const stato = sanitize(body.stato);
            const link = body.link_responsabilita ? sanitize(body.link_responsabilita) : null;

            if (!collectionName || !docId || !stato) return res.status(400).json({ error: 'Dati mancanti' });

            await db.collection(collectionName).doc(docId).set({
                stato: stato,
                link_responsabilita: link,
                ultimo_aggiornamento: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });

            return res.status(200).json({ success: true });
        }

        return res.status(400).json({ error: 'Azione non riconosciuta' });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Errore interno del server' });
    }
}

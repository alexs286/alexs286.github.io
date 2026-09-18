const admin = require('firebase-admin');

if (!admin.apps.length) {
    try {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_WORK);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
    } catch (e) {}
}

const db = admin.firestore();
const rateLimits = new Map();

const sanitize = (i) => typeof i === 'string' ? i.trim().substring(0, 1000).replace(/[<>]/g, '') : '';

const checkRateLimit = (ip) => {
    const now = Date.now();
    const limit = rateLimits.get(ip) || { count: 0, time: now };
    if (now - limit.time > 60000) { limit.count = 1; limit.time = now; } 
    else { limit.count++; }
    rateLimits.set(ip, limit);
    return limit.count > 50; 
};

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (checkRateLimit(clientIp)) return res.status(429).json({ error: 'Rate limit' });

    try {
        const action = req.query.action || (req.body && req.body.action);

        if (req.method === 'GET' && action === 'get_status') {
            const doc = await db.collection('stato del servizio').doc('current_status').get();
            return res.status(200).json(doc.exists ? doc.data() : { status: 'online' });
        }

        if (req.method === 'GET' && action === 'get_richieste') {
            const snap = await db.collection('richieste_supporto').orderBy('data', 'desc').limit(50).get();
            const r = [];
            snap.forEach(d => r.push({ id: d.id, ...d.data() }));
            return res.status(200).json(r);
        }

        if (req.method === 'POST' && action === 'login') {
            const { email, password } = req.body;
            const snap = await db.collection('utenti_dashboard').where('email', '==', String(email)).where('password', '==', String(password)).limit(1).get();
            if (snap.empty) return res.status(401).json({ error: 'Non autorizzato' });
            return res.status(200).json({ userId: snap.docs[0].id });
        }

        if (req.method === 'POST' && action === 'update_status') {
            const { stato, messaggio, versione } = req.body;
            const payload = {
                status: sanitize(stato),
                message: sanitize(messaggio),
                version: sanitize(versione),
                ultimo_aggiornamento: admin.firestore.FieldValue.serverTimestamp()
            };
            await db.collection('stato del servizio').doc('current_status').set(payload, { merge: true });
            return res.status(200).json({ success: true });
        }

        return res.status(404).json({ error: 'Azione non trovata' });
    } catch (error) {
        return res.status(500).json({ error: 'Errore server' });
    }
}

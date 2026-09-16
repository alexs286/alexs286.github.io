const admin = require('firebase-admin');

if (!admin.apps.length) {
    try {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_WORK);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
    } catch (e) {
        console.error("Errore inizializzazione Firebase:", e);
    }
}

const db = admin.firestore();
const rateLimits = new Map();
const sanitizeOutput = (input) => {
    if (typeof input !== 'string') return '';
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
    return limit.count > 20; 
};

const delay = (ms) => new Promise(res => setTimeout(res, ms));

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') return res.status(200).end();
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (checkRateLimit(clientIp)) {
        await delay(2000);
        return res.status(429).json({ error: 'Troppe richieste. Riprova tra 1 minuto.' });
    }
    try {
        if (req.method === 'GET') {
            const statusRef = db.collection('stato del servizio').doc('current_status');
            const doc = await statusRef.get();
            if (!doc.exists) {
                return res.status(404).json({ error: 'Dato non trovato nel database' });
            }
            const data = doc.data();
            const safeResponse = {
                stato: sanitizeOutput(data.stato), 
                link_responsabilita: data.link_responsabilita ? sanitizeOutput(data.link_responsabilita) : null
            };
            return res.status(200).json(safeResponse);
        }
        return res.status(405).json({ error: 'Metodo non consentito. Usa GET.' });
    } catch (error) {
        console.error("Errore Server:", error);
        return res.status(500).json({ error: 'Errore interno del server' });
    }
}

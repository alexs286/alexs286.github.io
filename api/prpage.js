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

const sanitizeInput = (input) => {
    if (typeof input !== 'string') return '';
    return input.trim().substring(0, 1000).replace(/[<>]/g, '');
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
    return limit.count > 30; 
};

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (checkRateLimit(clientIp)) {
        return res.status(429).json({ error: 'Troppe richieste. Riprova più tardi.' });
    }

    try {
        const url = req.url || '';

        if (req.method === 'GET' && url.includes('richieste')) {
            const snapshot = await db.collection('richieste_supporto')
                .orderBy('data', 'desc')
                .limit(50)
                .get();
            
            const richieste = [];
            snapshot.forEach(doc => {
                richieste.push({ id: doc.id, ...doc.data() });
            });
            return res.status(200).json(richieste);
        }

        if (req.method === 'GET' && url.includes('dashboard')) {
            const userId = sanitizeInput(req.query.userId);
            if (!userId) return res.status(400).json({ error: 'ID utente mancante' });

            const doc = await db.collection('utenti_dashboard').doc(userId).get();
            if (!doc.exists) return res.status(404).json({ error: 'Utente non trovato' });

            return res.status(200).json(doc.data());
        }

        if (req.method === 'POST' && url.includes('dashboard')) {
            const { action, userId, ...payload } = req.body;
            
            if (action === 'update_user') {
                const sUserId = sanitizeInput(userId);
                if (!sUserId) return res.status(400).json({ error: 'ID utente mancante' });

                const cleanPayload = {};
                for (const [key, value] of Object.entries(payload)) {
                    cleanPayload[key] = sanitizeInput(value);
                }
                
                cleanPayload.ultimo_aggiornamento = admin.firestore.FieldValue.serverTimestamp();

                await db.collection('utenti_dashboard').doc(sUserId).set(cleanPayload, { merge: true });
                return res.status(200).json({ success: true, message: 'Dati utente aggiornati' });
            }
        }

        if (req.method === 'POST' && url.includes('servizio')) {
            const { status, message, version } = req.body;
            
            const cleanPayload = {
                status: sanitizeInput(status),
                message: sanitizeInput(message),
                version: sanitizeInput(version),
                ultimo_aggiornamento: admin.firestore.FieldValue.serverTimestamp()
            };

            await db.collection('configurazione_sistema').doc('stato_servizio').set(cleanPayload, { merge: true });
            return res.status(200).json({ success: true, message: 'Stato servizio aggiornato' });
        }

        return res.status(404).json({ error: 'Endpoint non riconosciuto' });
    } catch (error) {
        console.error('API Error:', error);
        return res.status(500).json({ error: 'Errore interno del server' });
    }
}

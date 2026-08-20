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

const sanitizeInput = (input) => {
    if (typeof input !== 'string') return '';
    return input.trim().substring(0, 150).replace(/[<>]/g, '');
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
    return limit.count > 10;
};

const delay = (ms) => new Promise(res => setTimeout(res, ms));

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    if (checkRateLimit(clientIp)) {
        await delay(2000);
        return res.status(429).json({ error: 'Troppi tentativi. Riprova più tardi.' });
    }

    try {
        if (req.method === 'GET') {
            const userId = sanitizeInput(req.query.userId);
            if (!userId) return res.status(400).json({ error: 'ID mancante' });
            
            const doc = await db.collection('utenti_dashboard').doc(userId).get();
            if (!doc.exists) return res.status(404).json({ error: 'Utente non trovato' });
            
            return res.status(200).json(doc.data());
        } 
        
        if (req.method === 'POST') {
            const action = sanitizeInput(req.body.action);

            if (action === 'login') {
                const email = sanitizeInput(req.body.email);
                const password = sanitizeInput(req.body.password);

                if (!email || !password) {
                    await delay(1000);
                    return res.status(400).json({ error: 'Dati mancanti' });
                }

                const usersRef = db.collection('utenti_dashboard');
                const snapshot = await usersRef.where('email', '==', String(email)).where('password', '==', String(password)).limit(1).get();

                if (snapshot.empty) {
                    await delay(1500);
                    return res.status(401).json({ error: 'Credenziali non valide' });
                }

                return res.status(200).json({ success: true, userId: snapshot.docs[0].id });
            }

            if (action === 'recovery') {
                const email = sanitizeInput(req.body.email);
                const code = sanitizeInput(req.body.code);

                if (!email || !code) {
                    await delay(1000);
                    return res.status(400).json({ error: 'Dati mancanti' });
                }

                const usersRef = db.collection('utenti_dashboard');
                const snapshot = await usersRef.where('email', '==', String(email)).where('codici_sicurezza', 'array-contains', String(code)).limit(1).get();

                if (snapshot.empty) {
                    await delay(1500);
                    return res.status(401).json({ error: 'Dati non validi o codice errato' });
                }

                return res.status(200).json({ success: true, userId: snapshot.docs[0].id });
            }

            const { userId, type, message, userInfo } = req.body;
            const sUserId = sanitizeInput(userId);
            const sType = sanitizeInput(type);
            const sMessage = sanitizeInput(message);

            if (sUserId && sType) {
                await db.collection('richieste_supporto').add({
                    userId: sUserId,
                    tipo_richiesta: sType,
                    messaggio: sMessage,
                    dati_utente: typeof userInfo === 'object' ? userInfo : {},
                    data: admin.firestore.FieldValue.serverTimestamp(),
                    stato: 'Da gestire'
                });
                return res.status(200).json({ success: true });
            }

            return res.status(400).json({ error: 'Azione non riconosciuta' });
        }

        return res.status(405).json({ error: 'Metodo non consentito' });
    } catch (error) {
        return res.status(500).json({ error: 'Errore interno del server' });
    }
}

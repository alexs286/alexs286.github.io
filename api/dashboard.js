const admin = require('firebase-admin');
const crypto = require('crypto');

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
    res.setHeader('Access-Control-Allow-Origin', 'https://www.creatorweb.cc');
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
                const identifier = sanitizeInput(req.body.email).toLowerCase();

                const password = typeof req.body.password === 'string'
                    ? req.body.password
                    : '';

                if (!identifier || !password) {
                    await delay(1000);
                    return res.status(400).json({
                        error: 'Dati mancanti'
                    });
                }

                const usersRef = db.collection('utenti_dashboard');

                let snapshot = await usersRef
                    .where('email', '==', identifier)
                    .limit(5)
                    .get();

                if (snapshot.empty) {
                    snapshot = await usersRef
                        .where('nome_utente', '==', identifier)
                        .limit(5)
                        .get();
                }

                const matchedUser = snapshot.docs.find(doc =>
                    doc.data().password === password
                );

                if (!matchedUser) {
                    await delay(1500);
                    return res.status(401).json({
                        error: 'Credenziali non valide'
                    });
                }

                return res.status(200).json({
                    success: true,
                    userId: matchedUser.id
                });
            }

            if (action === 'recovery') {
                const email = sanitizeInput(req.body.email).toLowerCase();

                const code = sanitizeInput(req.body.code)
                    .replace(/[\s-]/g, '')
                    .toUpperCase();

                if (!email || !code) {
                    await delay(1000);
                    return res.status(400).json({
                        error: 'Dati mancanti'
                    });
                }

                if (!/^[A-F0-9]{12}$/.test(code)) {
                    return res.status(401).json({
                        error: 'Email o codice non validi'
                    });
                }

                const usersRef = db.collection('utenti_dashboard');

                const snapshot = await usersRef
                    .where('email', '==', email)
                    .limit(1)
                    .get();

                if (snapshot.empty) {
                    await delay(1500);
                    return res.status(401).json({
                        error: 'Email o codice non validi'
                    });
                }

                const userRef = snapshot.docs[0].ref;

                const codeHash = crypto
                    .createHash('sha256')
                    .update(code)
                    .digest('hex');

                const accepted = await db.runTransaction(async transaction => {
                    const freshDoc = await transaction.get(userRef);

                    if (!freshDoc.exists) return false;

                    const user = freshDoc.data();

                    const hashes = Array.isArray(user.codici_sicurezza_hash)
                        ? user.codici_sicurezza_hash
                        : [];

                    const index = hashes.findIndex(savedHash => {
                        if (
                            typeof savedHash !== 'string' ||
                            !/^[a-f0-9]{64}$/i.test(savedHash)
                        ) {
                            return false;
                        }

                        return crypto.timingSafeEqual(
                            Buffer.from(savedHash, 'hex'),
                            Buffer.from(codeHash, 'hex')
                        );
                    });

                    if (index === -1) return false;

                    const remainingCodes = [...hashes];
                    remainingCodes.splice(index, 1);

                    transaction.update(userRef, {
                        codici_sicurezza_hash: remainingCodes,
                        codici_sicurezza_usati:
                            admin.firestore.FieldValue.increment(1),
                        ultimo_uso_codice_sicurezza:
                            admin.firestore.FieldValue.serverTimestamp()
                    });

                    return true;
                });

                if (!accepted) {
                    await delay(1500);
                    return res.status(401).json({
                        error: 'Email o codice non validi'
                    });
                }

                return res.status(200).json({
                    success: true,
                    userId: snapshot.docs[0].id
                });
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

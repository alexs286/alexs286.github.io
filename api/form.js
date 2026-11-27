const admin = require('firebase-admin');

const ALLOWED_ORIGINS = new Set([
    'https://creatorweb.cc',
    'https://www.creatorweb.cc'
]);

function getFirestoreDb() {
    if (admin.apps.length) {
        return admin.firestore();
    }

    const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;

    if (!rawServiceAccount) {
        throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_WORK environment variable.');
    }

    let serviceAccount;
    if (typeof rawServiceAccount === 'string') {
        try {
            serviceAccount = JSON.parse(rawServiceAccount);
        } catch (e) {
            throw new Error('Invalid JSON format in FIREBASE_SERVICE_ACCOUNT_WORK');
        }
    } else {
        serviceAccount = rawServiceAccount;
    }

    if (serviceAccount.private_key && typeof serviceAccount.private_key === 'string') {
        serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
    }

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });

    return admin.firestore();
}

export default async function handler(req, res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    const origin = req.headers.origin;

    if (origin) {
        if (ALLOWED_ORIGINS.has(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        } else {
            return res.status(403).json({
                error: 'Origin non autorizzata'
            });
        }
    } else {
        res.setHeader('Access-Control-Allow-Origin', 'https://www.creatorweb.cc');
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'no-store, max-age=0');

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    let db;
    try {
        db = getFirestoreDb();
    } catch (dbError) {
        console.error('Firebase initialization error:', dbError);
        return res.status(500).json({
            error: 'Database uninitialized'
        });
    }

    try {
        if (req.method === 'GET') {
            const statusSnapshot = await db
                .collection('stato del servizio')
                .doc('current_status')
                .get();

            const statusData = statusSnapshot.exists
                ? statusSnapshot.data()
                : {};

            return res.status(200).json({
                blocked: statusData.limite_clienti_attivo === true
            });
        }

        if (req.method === 'POST') {
            const content = req.body?.content;

            if (typeof content !== 'string' || !content.trim()) {
                return res.status(400).json({
                    error: 'Invalid content format'
                });
            }

            if (content.length > 50000) {
                return res.status(413).json({
                    error: 'Payload limits exceeded'
                });
            }

            const statusSnapshot = await db
                .collection('stato del servizio')
                .doc('current_status')
                .get();

            const statusData = statusSnapshot.exists
                ? statusSnapshot.data()
                : {};

            if (statusData.limite_clienti_attivo === true) {
                return res.status(503).json({
                    success: false,
                    code: 'REQUESTS_DISABLED',
                    error: 'Le nuove richieste sono temporaneamente sospese.'
                });
            }

            const collectionRef = db.collection('form_richieste');

            const newDoc = await collectionRef.add({
                content: content.trim(),
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });

            return res.status(200).json({
                id: newDoc.id,
                success: true
            });
        }

        res.setHeader('Allow', ['GET', 'POST', 'OPTIONS']);
        return res.status(405).json({
            error: 'Method Not Allowed'
        });

    } catch (error) {
        console.error('Form API error:', error);
        return res.status(500).json({
            error: 'Errore durante la gestione della richiesta.'
        });
    }
}

const admin = require('firebase-admin');

const ALLOWED_ORIGINS = new Set([
    'https://creatorweb.cc',
    'https://www.creatorweb.cc'
]);

let db;

try {
    const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;

    if (!rawServiceAccount) {
        throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_WORK');
    }

    const serviceAccount = typeof rawServiceAccount === 'string'
        ? JSON.parse(rawServiceAccount)
        : rawServiceAccount;

    if (!admin.apps.length) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
    }

    db = admin.firestore();

} catch (error) {
    console.error('Firebase initialization error:', error);
}

export default async function handler(req, res) {

    const origin = req.headers.origin;

    if (origin && !ALLOWED_ORIGINS.has(origin)) {
        return res.status(403).json({
            error: 'Origin non autorizzata'
        });
    }

    res.setHeader(
        'Access-Control-Allow-Origin',
        origin || 'https://www.creatorweb.cc'
    );

    res.setHeader(
        'Access-Control-Allow-Methods',
        'GET, POST, OPTIONS'
    );

    res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type'
    );

    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'no-store, max-age=0');

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    if (!db) {
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

            if (!content || typeof content !== 'string') {
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
                content,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });

            return res.status(200).json({
                id: newDoc.id,
                success: true
            });
        }


        res.setHeader('Allow', ['GET', 'POST', 'OPTIONS']);

        return res.status(405).end();


    } catch (error) {

        console.error('Form API error:', error);

        return res.status(500).json({
            error: 'Errore durante la gestione della richiesta.'
        });

    }
}

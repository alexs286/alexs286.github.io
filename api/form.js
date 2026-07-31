import admin from 'firebase-admin';

if (!admin.apps.length) {
  try {
    const serviceAccount = typeof process.env.FIREBASE_SERVICE_ACCOUNT_WORK === 'string'
      ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_WORK)
      : process.env.FIREBASE_SERVICE_ACCOUNT_WORK;

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  } catch (error) {
    console.error('Errore durante l\'inizializzazione dei dati:', error);
  }
}

const db = admin.firestore();

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Metodo non consentito. Utilizzare POST.' });
  }

  try {
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: 'Payload del form vuoto o non valido.' });
    }

    const parsedData = typeof content === 'string' ? JSON.parse(content) : content;

    const docData = {
      ...parsedData,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('richieste_preventivo').add(docData);

    return res.status(200).json({
      success: true,
      message: 'Richiesta ricevuta e salvata con successo!',
      id: docRef.id
    });

  } catch (error) {
    console.error('Errore durante il salvataggio dei dati:', error);
    return res.status(500).json({ error: 'Errore interno del server durante il salvataggio.' });
  }
}

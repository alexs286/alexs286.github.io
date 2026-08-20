const admin = require('firebase-admin');

if (!admin.apps.length) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_WORK);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  } catch (error) {
    console.error("Errore inizializzazione Firebase:", error);
  }
}

const db = admin.firestore();

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    if (req.method === 'GET') {
      const { userId } = req.query;
      if (!userId) return res.status(400).json({ error: 'User ID mancante' });

      const doc = await db.collection('utenti_dashboard').doc(userId).get();
      if (!doc.exists) return res.status(404).json({ error: 'Utente non trovato' });

      return res.status(200).json(doc.data());
    } 
    
    if (req.method === 'POST') {
      const { userId, type, message, userInfo } = req.body;
      if (!userId || !type) return res.status(400).json({ error: 'Dati mancanti' });

      await db.collection('richieste_supporto').add({
        userId,
        tipo_richiesta: type,
        messaggio: message || '',
        dati_utente: userInfo,
        data: admin.firestore.FieldValue.serverTimestamp(),
        stato: 'Da gestire'
      });

      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: 'Metodo non consentito' });
  } catch (error) {
    return res.status(500).json({ error: 'Errore interno del server' });
  }
}

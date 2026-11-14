'use strict';

const admin = require('firebase-admin');
const crypto = require('crypto');

if (!admin.apps.length) {
  const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;
  if (!rawServiceAccount) throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_WORK');
  let serviceAccount;
  try {
    serviceAccount = typeof rawServiceAccount === 'string' ? JSON.parse(rawServiceAccount) : rawServiceAccount;
  } catch (_error) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_WORK non contiene un JSON valido');
  }
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}

const db = admin.firestore();
const ALLOWED_ORIGINS = new Set(['https://creatorweb.cc', 'https://www.creatorweb.cc']);
const OTP_TTL_MS = 10 * 60 * 1000;

function json(res, status, body) {
  return res.status(status).json(body);
}

function setCors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

function clean(value, max = 500) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

function validId(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const raw = typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : '';
  return clean(raw || req.socket?.remoteAddress || 'unknown', 100);
}

function hashHex(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function getOtpHash(quoteId, verificationId, code) {
  const secret = process.env.PREVENTIVI_OTP_SECRET;
  if (!secret || secret.length < 32) throw Object.assign(new Error('Configurazione OTP mancante o non sicura.'), { status: 503 });
  return crypto.createHmac('sha256', secret).update(`${quoteId}:${verificationId}:${code}`).digest('hex');
}

function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
  catch (_error) { return false; }
}

function maskEmail(email) {
  const [name, domain] = String(email || '').split('@');
  if (!name || !domain) return '';
  const visible = name.length <= 2 ? name[0] : name.slice(0, 2);
  return `${visible}${'*'.repeat(Math.max(2, name.length - visible.length))}@${domain}`;
}

function serializeDate(value, fallback) {
  if (value && typeof value.toDate === 'function') return value.toDate().toISOString();
  if (value instanceof Date) return value.toISOString();
  return fallback || null;
}

function isExpired(quote) {
  const validUntil = quote.validUntil && typeof quote.validUntil.toDate === 'function'
    ? quote.validUntil.toDate().getTime()
    : new Date(quote.validUntilIso || 0).getTime();
  return !Number.isFinite(validUntil) || Date.now() > validUntil;
}

function getQuoteRef(id) { return db.collection('preventivi_emessi').doc(id); }

async function sendOtpEmail(email, clientName, quoteNumber, code) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM_EMAIL;
  if (!apiKey || !from) throw Object.assign(new Error('Invio email non configurato: mancano RESEND_API_KEY o RESEND_FROM_EMAIL.'), { status: 503 });

  const safeName = clean(clientName, 160) || 'Cliente';
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from,
      to: [email],
      subject: `Codice di verifica per il preventivo ${quoteNumber}`,
      text: `Ciao ${safeName},\n\nIl tuo codice di verifica per visualizzare e confermare il preventivo ${quoteNumber} è: ${code}\n\nIl codice è valido per 10 minuti. Se non hai richiesto questa operazione, ignora il messaggio.\n\nCreatorWeb`,
      html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#172033"><h2>Verifica dell'indirizzo email</h2><p>Ciao ${safeName.replace(/[&<>"']/g, '')},</p><p>Inserisci questo codice per procedere con il preventivo <strong>${clean(quoteNumber, 80)}</strong>:</p><p style="font-size:30px;font-weight:800;letter-spacing:7px;padding:16px;background:#f1f5f9;border-radius:10px;text-align:center">${code}</p><p>Il codice è valido per 10 minuti. Se non hai richiesto questa operazione, ignora il messaggio.</p><p>CreatorWeb</p></div>`
    })
  });
  if (!response.ok) {
    const details = await response.text().catch(() => '');
    console.error('Resend error:', response.status, details.slice(0, 500));
    throw Object.assign(new Error('Non è stato possibile inviare il codice email. Riprova più tardi.'), { status: 502 });
  }
}

async function enforceOtpRateLimit(id, ip) {
  const ref = db.collection('preventivi_rate_limits').doc(hashHex(`${id}:${ip}`).slice(0, 48));
  const now = Date.now();
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const data = snap.exists ? snap.data() : {};
    const windowStart = Number(data.windowStart || 0);
    const count = now - windowStart > 15 * 60 * 1000 ? 0 : Number(data.count || 0);
    if (count >= 3) throw Object.assign(new Error('Hai richiesto troppi codici. Attendi 15 minuti prima di riprovare.'), { status: 429 });
    tx.set(ref, { windowStart: count === 0 ? now : windowStart, count: count + 1, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
  });
}

async function requestOtp(req, res, id, ip) {
  const quoteRef = getQuoteRef(id);
  const quoteSnap = await quoteRef.get();
  if (!quoteSnap.exists) return json(res, 404, { error: 'Preventivo non trovato.' });
  const quote = quoteSnap.data() || {};
  if (quote.status !== 'pending') return json(res, 409, { error: 'Questo preventivo non è più in attesa di accettazione.' });
  if (isExpired(quote)) return json(res, 410, { error: 'Il preventivo è scaduto. Contatta CreatorWeb per richiederne uno aggiornato.' });
  if (!quote.client?.email) return json(res, 409, { error: 'Il preventivo non contiene un indirizzo email valido.' });

  await enforceOtpRateLimit(id, ip);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const verificationId = crypto.randomBytes(16).toString('hex');
  const codeHash = getOtpHash(id, verificationId, code);
  await db.collection('preventivi_verifiche').doc(id).set({
    quoteId: id,
    verificationId,
    codeHash,
    attempts: 0,
    used: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: admin.firestore.Timestamp.fromDate(new Date(Date.now() + OTP_TTL_MS)),
    ipHash: hashHex(ip)
  });

  try {
    await sendOtpEmail(quote.client.email, quote.client.name, quote.quoteNumber, code);
  } catch (error) {
    await db.collection('preventivi_verifiche').doc(id).delete().catch(() => {});
    throw error;
  }
  return json(res, 200, { success: true, verificationId, emailMasked: maskEmail(quote.client.email), expiresInSeconds: OTP_TTL_MS / 1000 });
}

function buildAuditHash(payload) {
  const secret = process.env.ACCEPTANCE_AUDIT_SECRET;
  if (!secret || secret.length < 32) throw Object.assign(new Error('Configurazione registro di accettazione mancante o non sicura.'), { status: 503 });
  return crypto.createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex');
}

async function registerDecision(req, res, id, body, ip, decision) {
  const verificationId = clean(body.verificationId, 64);
  const code = clean(body.code, 6);
  if (!/^[a-f0-9]{32}$/i.test(verificationId) || !/^\d{6}$/.test(code)) {
    return json(res, 400, { error: 'Inserisci il codice di verifica ricevuto via email.' });
  }

  const quoteRef = getQuoteRef(id);
  const verificationRef = db.collection('preventivi_verifiche').doc(id);
  const eventId = crypto.randomBytes(12).toString('hex');
  const eventRef = quoteRef.collection('eventi').doc(eventId);
  const userAgent = clean(req.headers['user-agent'] || '', 500);
  const requestTimeIso = new Date().toISOString();
  let outcome = null;

  await db.runTransaction(async tx => {
    const [quoteSnap, verificationSnap] = await Promise.all([tx.get(quoteRef), tx.get(verificationRef)]);
    if (!quoteSnap.exists) { outcome = { status: 404, error: 'Preventivo non trovato.' }; return; }
    if (!verificationSnap.exists) { outcome = { status: 400, error: 'Richiedi un nuovo codice di verifica.' }; return; }
    const quote = quoteSnap.data() || {};
    const verification = verificationSnap.data() || {};
    if (quote.status !== 'pending') { outcome = { status: 409, error: 'Il preventivo ha già ricevuto una risposta.' }; return; }
    if (isExpired(quote)) { outcome = { status: 410, error: 'Il preventivo è scaduto.' }; return; }
    if (verification.used || verification.verificationId !== verificationId) { outcome = { status: 400, error: 'Codice non valido o già utilizzato. Richiedine uno nuovo.' }; return; }
    const expiry = verification.expiresAt && typeof verification.expiresAt.toDate === 'function' ? verification.expiresAt.toDate().getTime() : 0;
    if (!expiry || Date.now() > expiry) { outcome = { status: 410, error: 'Il codice è scaduto. Richiedine uno nuovo.' }; return; }
    const expected = getOtpHash(id, verificationId, code);
    const matches = safeEqualHex(expected, verification.codeHash);
    if (!matches) {
      const attempts = Number(verification.attempts || 0) + 1;
      tx.update(verificationRef, { attempts, used: attempts >= 5 });
      outcome = { status: 400, error: attempts >= 5 ? 'Troppi tentativi errati. Richiedi un nuovo codice.' : `Codice non corretto. Tentativi rimasti: ${5 - attempts}.` };
      return;
    }

    const customerName = clean(body.customerName, 160);
    const declarations = body.declarations && typeof body.declarations === 'object' ? body.declarations : {};
    if (!customerName) { outcome = { status: 400, error: 'Inserisci il nome della persona che effettua la dichiarazione.' }; return; }
    if (decision === 'accepted') {
      if (declarations.acceptedTerms !== true || declarations.privacyAcknowledged !== true) {
        outcome = { status: 400, error: 'Per accettare devi confermare il preventivo e dichiarare di aver preso visione dell’informativa privacy.' }; return;
      }
      if (quote.client?.type === 'professional' && declarations.specificApproval !== true) {
        outcome = { status: 400, error: 'È richiesta anche l’approvazione specifica delle clausole per i clienti professionali.' }; return;
      }
      if (quote.client?.type === 'consumer' && declarations.earlyStartRequested === true && declarations.earlyStartAcknowledged !== true) {
        outcome = { status: 400, error: 'Per chiedere l’avvio anticipato devi confermare anche la relativa dichiarazione.' }; return;
      }
    }

    const auditPayload = {
      eventId,
      decision,
      quoteId: id,
      quoteNumber: quote.quoteNumber || '',
      quoteHash: quote.quoteHash || '',
      clientEmail: quote.client?.email || '',
      customerName,
      requestTimeIso,
      ip,
      userAgent,
      verificationMethod: 'email_otp',
      verificationId,
      termsVersion: quote.termsVersion || '',
      declarations: {
        acceptedTerms: declarations.acceptedTerms === true,
        privacyAcknowledged: declarations.privacyAcknowledged === true,
        specificApproval: declarations.specificApproval === true,
        earlyStartRequested: declarations.earlyStartRequested === true,
        earlyStartAcknowledged: declarations.earlyStartAcknowledged === true
      }
    };
    const auditHash = buildAuditHash(auditPayload);
    tx.update(verificationRef, { used: true, usedAt: admin.firestore.FieldValue.serverTimestamp() });
    tx.update(quoteRef, {
      status: decision,
      [decision === 'accepted' ? 'acceptance' : 'rejection']: {
        ...auditPayload,
        auditHash,
        recordedAt: admin.firestore.FieldValue.serverTimestamp()
      },
      respondedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    tx.set(eventRef, { ...auditPayload, auditHash, recordedAt: admin.firestore.FieldValue.serverTimestamp() });
    outcome = { status: 200, success: true, decision, eventId, auditHash, requestTimeIso, quoteNumber: quote.quoteNumber };
  });

  if (!outcome) return json(res, 500, { error: 'Non è stato possibile registrare la risposta.' });
  if (outcome.error) return json(res, outcome.status, { error: outcome.error });
  return json(res, 200, outcome);
}

function publicQuoteData(id, quote) {
  const client = quote.client || {};
  const acceptance = quote.acceptance || null;
  const rejection = quote.rejection || null;
  return {
    id,
    quoteNumber: quote.quoteNumber || '',
    client: {
      name: client.name || '',
      type: client.type || 'consumer',
      address: client.address || '',
      emailMasked: maskEmail(client.email || '')
    },
    project: quote.project || {},
    items: Array.isArray(quote.items) ? quote.items : [],
    totalCents: Number(quote.totalCents || 0),
    currency: quote.currency || 'EUR',
    terms: quote.terms || {},
    termsVersion: quote.termsVersion || '',
    termsUrl: quote.termsUrl || 'https://www.creatorweb.cc/termini.html',
    status: quote.status || 'pending',
    createdAt: serializeDate(quote.createdAt, quote.createdAtIso),
    validUntil: serializeDate(quote.validUntil, quote.validUntilIso),
    expired: isExpired(quote),
    acceptance: acceptance ? {
      eventId: acceptance.eventId,
      customerName: acceptance.customerName,
      requestTimeIso: acceptance.requestTimeIso,
      auditHash: acceptance.auditHash
    } : null,
    rejection: rejection ? {
      eventId: rejection.eventId,
      customerName: rejection.customerName,
      requestTimeIso: rejection.requestTimeIso,
      auditHash: rejection.auditHash
    } : null
  };
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.headers.origin && !ALLOWED_ORIGINS.has(req.headers.origin)) return json(res, 403, { error: 'Origine non autorizzata.' });

  const id = clean(req.method === 'GET' ? req.query?.id : req.body?.id, 100);
  if (!validId(id)) return json(res, 400, { error: 'Link del preventivo non valido o incompleto.' });
  const ip = getClientIp(req);

  try {
    if (req.method === 'GET') {
      const snapshot = await getQuoteRef(id).get();
      if (!snapshot.exists) return json(res, 404, { error: 'Preventivo non trovato. Verifica il link ricevuto.' });
      const quote = snapshot.data() || {};
      return json(res, 200, { quote: publicQuoteData(id, quote) });
    }
    if (req.method !== 'POST') return json(res, 405, { error: 'Metodo non consentito.' });

    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const action = clean(body.action, 40);
    if (action === 'request_otp') return await requestOtp(req, res, id, ip);
    if (action === 'accept') return await registerDecision(req, res, id, body, ip, 'accepted');
    if (action === 'reject') return await registerDecision(req, res, id, body, ip, 'rejected');
    return json(res, 400, { error: 'Operazione non riconosciuta.' });
  } catch (error) {
    console.error('Preventivo API error:', error);
    return json(res, error.status || 500, { error: error.status ? error.message : 'Errore interno del server.' });
  }
};

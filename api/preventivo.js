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
  if (!serviceAccount || typeof serviceAccount !== 'object' || !serviceAccount.project_id || !serviceAccount.private_key || !serviceAccount.client_email) {
    throw new Error('Credenziali service account incomplete');
  }
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}

const db = admin.firestore();
const ALLOWED_ORIGINS = new Set(['https://creatorweb.cc', 'https://www.creatorweb.cc']);
const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_WINDOW_MS = 15 * 60 * 1000;
const OTP_MAX_REQUESTS = 3;
const OTP_MAX_ATTEMPTS = 5;
const MAX_BODY_BYTES = 64 * 1024;
const ALLOWED_CURRENCIES = new Set(['EUR', 'USD', 'GBP', 'CHF']);
const ALLOWED_CLIENT_TYPES = new Set(['consumer', 'professional']);
const ALLOWED_STATUSES = new Set(['pending', 'accepted', 'rejected']);

function httpError(status, message) {
  return Object.assign(new Error(message), { status, expose: true });
}

function json(res, status, body) {
  return res.status(status).json(body);
}

function setCors(req, res) {
  const origin = typeof req.headers.origin === 'string' ? req.headers.origin.trim() : '';
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
}

function clean(value, max = 500) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, max);
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"'`]/g, ch => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '`': '&#96;'
  }[ch]));
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

function sanitizeData(value, depth = 0, maxItems = 100) {
  if (depth > 6 || value === null || value === undefined) return null;
  if (typeof value === 'string') return clean(value, 2000);
  if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
  if (typeof value === 'boolean') return value;
  if (value && typeof value.toDate === 'function') return value.toDate().toISOString();
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.toISOString() : null;
  if (Array.isArray(value)) {
    return value.slice(0, maxItems).map(item => sanitizeData(item, depth + 1, maxItems));
  }
  if (isPlainObject(value)) {
    const out = {};
    const keys = Object.keys(value).slice(0, maxItems);
    for (const key of keys) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
      const safeKey = clean(key, 120);
      if (!safeKey) continue;
      out[safeKey] = sanitizeData(value[key], depth + 1, maxItems);
    }
    return out;
  }
  return null;
}

function validId(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const trimmed = email.trim();
  if (trimmed.length < 5 || trimmed.length > 254 || /[\r\n]/.test(trimmed)) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(trimmed);
}

function getClientIp(req) {
  const trustProxy = process.env.TRUST_PROXY === '1' || process.env.VERCEL === '1';
  if (trustProxy) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length > 0) {
      const parts = forwarded.split(',').map(p => p.trim()).filter(Boolean);
      const candidate = parts[parts.length - 1] || '';
      if (/^[0-9a-fA-F:.]{3,45}$/.test(candidate)) return candidate;
    }
  }
  const raw = typeof req.socket?.remoteAddress === 'string' ? req.socket.remoteAddress : '';
  return /^[0-9a-fA-F:.]{3,45}$/.test(raw) ? raw : 'unknown';
}

function hashHex(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function getOtpHash(quoteId, verificationId, code) {
  const secret = process.env.PREVENTIVI_OTP_SECRET;
  if (!secret || secret.length < 32) throw httpError(503, 'Servizio temporaneamente non disponibile.');
  return crypto.createHmac('sha256', secret).update(`${quoteId}:${verificationId}:${code}`).digest('hex');
}

function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length || a.length % 2 !== 0) return false;
  if (!/^[a-f0-9]+$/i.test(a) || !/^[a-f0-9]+$/i.test(b)) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch (_error) {
    return false;
  }
}

function maskEmail(email) {
  const raw = String(email || '').trim();
  const atIndex = raw.indexOf('@');
  if (atIndex <= 0) return '';
  const name = raw.slice(0, atIndex);
  const domain = raw.slice(atIndex + 1);
  if (!domain || !domain.includes('.')) return '';
  const visible = name.length <= 2 ? name[0] : name.slice(0, 2);
  return `${visible}${'*'.repeat(Math.max(2, name.length - visible.length))}@${domain}`;
}

function serializeDate(value, fallback) {
  if (value && typeof value.toDate === 'function') {
    const d = value.toDate();
    return Number.isFinite(d.getTime()) ? d.toISOString() : (fallback || null);
  }
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.toISOString() : (fallback || null);
  if (typeof fallback === 'string') {
    const d = new Date(fallback);
    return Number.isFinite(d.getTime()) ? d.toISOString() : null;
  }
  return null;
}

function isExpired(quote) {
  const rawMs = quote.validUntil && typeof quote.validUntil.toDate === 'function'
    ? quote.validUntil.toDate().getTime()
    : new Date(quote.validUntilIso || 0).getTime();
  return !Number.isFinite(rawMs) || rawMs <= 0 || Date.now() > rawMs;
}

function getQuoteRef(id) {
  return db.collection('preventivi_emessi').doc(id);
}

function parseJsonBody(req) {
  if (isPlainObject(req.body)) {
    const size = Buffer.byteLength(JSON.stringify(req.body), 'utf8');
    if (size > MAX_BODY_BYTES) throw httpError(413, 'Richiesta troppo grande.');
    return req.body;
  }
  if (typeof req.body === 'string') {
    if (Buffer.byteLength(req.body, 'utf8') > MAX_BODY_BYTES) throw httpError(413, 'Richiesta troppo grande.');
    try {
      const parsed = JSON.parse(req.body);
      if (!isPlainObject(parsed)) throw httpError(400, 'Formato richiesta non valido.');
      return parsed;
    } catch (err) {
      if (err.expose) throw err;
      throw httpError(400, 'JSON non valido.');
    }
  }
  throw httpError(400, 'Corpo della richiesta non valido.');
}

async function sendOtpEmail(email, clientName, quoteNumber, code) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM_EMAIL;
  if (!apiKey || !from) throw httpError(503, 'Servizio email non disponibile.');
  const safeName = clean(clientName, 160) || 'Cliente';
  const safeQuoteNumber = clean(quoteNumber, 80);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);
  let response;
  try {
    response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': hashHex(`${email}:${safeQuoteNumber}:${code}`)
      },
      signal: controller.signal,
      body: JSON.stringify({
        from,
        to: [email],
        subject: `Codice di verifica per il preventivo ${safeQuoteNumber}`,
        text: `Ciao ${safeName},\n\nIl tuo codice di verifica per visualizzare e confermare il preventivo ${safeQuoteNumber} è: ${code}\n\nIl codice è valido per 10 minuti. Se non hai richiesto questa operazione, ignora il messaggio.\n\nCreatorWeb`,
        html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#172033"><h2>Verifica dell'indirizzo email</h2><p>Ciao ${escapeHtml(safeName)},</p><p>Inserisci questo codice per procedere con il preventivo <strong>${escapeHtml(safeQuoteNumber)}</strong>:</p><p style="font-size:30px;font-weight:800;letter-spacing:7px;padding:16px;background:#f1f5f9;border-radius:10px;text-align:center">${escapeHtml(code)}</p><p>Il codice è valido per 10 minuti. Se non hai richiesto questa operazione, ignora il messaggio.</p><p>CreatorWeb</p></div>`
      })
    });
  } catch (_err) {
    throw httpError(502, 'Non è stato possibile inviare il codice email. Riprova più tardi.');
  } finally {
    clearTimeout(timeoutId);
  }
  if (!response.ok) {
    await response.text().catch(() => '');
    throw httpError(502, 'Non è stato possibile inviare il codice email. Riprova più tardi.');
  }
}

async function enforceOtpRateLimit(id, ip) {
  const ipHash = hashHex(ip);
  const ref = db.collection('preventivi_rate_limits').doc(hashHex(`${id}:${ipHash}`).slice(0, 48));
  const now = Date.now();
  await db.runTransaction(async tx => {
    const snap = await tx.get(ref);
    const data = snap.exists && isPlainObject(snap.data()) ? snap.data() : {};
    const windowStart = Number(data.windowStart || 0);
    const expiredWindow = !Number.isFinite(windowStart) || (now - windowStart > OTP_WINDOW_MS);
    const count = expiredWindow ? 0 : Number(data.count || 0);
    if (count >= OTP_MAX_REQUESTS) {
      throw httpError(429, 'Hai richiesto troppi codici. Attendi 15 minuti prima di riprovare.');
    }
    tx.set(ref, {
      quoteId: id,
      ipHash,
      windowStart: count === 0 ? now : windowStart,
      count: count + 1,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      expireAt: admin.firestore.Timestamp.fromDate(new Date(now + OTP_WINDOW_MS + 60000))
    }, { merge: true });
  });
}

async function requestOtp(_req, res, id, ip) {
  const quoteRef = getQuoteRef(id);
  const quoteSnap = await quoteRef.get();
  if (!quoteSnap.exists) return json(res, 404, { error: 'Preventivo non trovato.' });
  const quote = quoteSnap.data() || {};
  if (quote.status !== 'pending') return json(res, 409, { error: 'Questo preventivo non è più in attesa di accettazione.' });
  if (isExpired(quote)) return json(res, 410, { error: 'Il preventivo è scaduto. Contatta CreatorWeb per richiederne uno aggiornato.' });
  const clientEmail = typeof quote.client?.email === 'string' ? quote.client.email.trim() : '';
  if (!isValidEmail(clientEmail)) return json(res, 409, { error: 'Il preventivo non contiene un indirizzo email valido.' });
  await enforceOtpRateLimit(id, ip);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const verificationId = crypto.randomBytes(16).toString('hex');
  const codeHash = getOtpHash(id, verificationId, code);
  const expiresAtDate = new Date(Date.now() + OTP_TTL_MS);
  const verificationRef = db.collection('preventivi_verifiche').doc(id);
  await verificationRef.set({
    quoteId: id,
    verificationId,
    codeHash,
    attempts: 0,
    used: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: admin.firestore.Timestamp.fromDate(expiresAtDate),
    expireAt: admin.firestore.Timestamp.fromDate(new Date(expiresAtDate.getTime() + 3600000)),
    ipHash: hashHex(ip)
  });
  try {
    await sendOtpEmail(clientEmail, quote.client?.name, quote.quoteNumber, code);
  } catch (error) {
    await verificationRef.delete().catch(() => {});
    throw error;
  }
  return json(res, 200, {
    success: true,
    verificationId,
    emailMasked: maskEmail(clientEmail),
    expiresInSeconds: OTP_TTL_MS / 1000
  });
}

function buildAuditHash(payload) {
  const secret = process.env.ACCEPTANCE_AUDIT_SECRET;
  if (!secret || secret.length < 32) throw httpError(503, 'Servizio temporaneamente non disponibile.');
  return crypto.createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex');
}

async function registerDecision(req, res, id, body, ip, decision) {
  const verificationId = clean(body.verificationId, 64).toLowerCase();
  const code = clean(body.code, 6);
  if (!/^[a-f0-9]{32}$/.test(verificationId) || !/^\d{6}$/.test(code)) {
    return json(res, 400, { error: 'Inserisci il codice di verifica ricevuto via email.' });
  }
  const customerName = clean(body.customerName, 160);
  const declarations = isPlainObject(body.declarations) ? body.declarations : {};
  if (!customerName) {
    return json(res, 400, { error: 'Inserisci il nome della persona che effettua la dichiarazione.' });
  }
  const quoteRef = getQuoteRef(id);
  const verificationRef = db.collection('preventivi_verifiche').doc(id);
  const eventId = crypto.randomBytes(12).toString('hex');
  const eventRef = quoteRef.collection('eventi').doc(eventId);
  const userAgent = clean(req.headers['user-agent'] || '', 300);
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
    if (verification.used === true || verification.quoteId !== id || verification.verificationId !== verificationId) {
      outcome = { status: 400, error: 'Codice non valido o già utilizzato. Richiedine uno nuovo.' };
      return;
    }
    const expiry = verification.expiresAt && typeof verification.expiresAt.toDate === 'function' ? verification.expiresAt.toDate().getTime() : 0;
    if (!expiry || Date.now() > expiry) {
      tx.update(verificationRef, { used: true, expiredAt: admin.firestore.FieldValue.serverTimestamp() });
      outcome = { status: 410, error: 'Il codice è scaduto. Richiedine uno nuovo.' };
      return;
    }
    const currentAttempts = Number(verification.attempts || 0);
    if (currentAttempts >= OTP_MAX_ATTEMPTS) {
      tx.update(verificationRef, { used: true });
      outcome = { status: 429, error: 'Troppi tentativi errati. Richiedi un nuovo codice.' };
      return;
    }
    const expected = getOtpHash(id, verificationId, code);
    const matches = safeEqualHex(expected, verification.codeHash);
    if (!matches) {
      const attempts = currentAttempts + 1;
      const locked = attempts >= OTP_MAX_ATTEMPTS;
      tx.update(verificationRef, { attempts, used: locked });
      outcome = {
        status: locked ? 429 : 400,
        error: locked ? 'Troppi tentativi errati. Richiedi un nuovo codice.' : `Codice non corretto. Tentativi rimasti: ${OTP_MAX_ATTEMPTS - attempts}.`
      };
      return;
    }
    const clientType = ALLOWED_CLIENT_TYPES.has(quote.client?.type) ? quote.client.type : 'consumer';
    if (decision === 'accepted') {
      if (declarations.acceptedTerms !== true || declarations.privacyAcknowledged !== true) {
        outcome = { status: 400, error: 'Per accettare devi confermare il preventivo e dichiarare di aver preso visione dell’informativa privacy.' };
        return;
      }
      if (clientType === 'professional' && declarations.specificApproval !== true) {
        outcome = { status: 400, error: 'È richiesta anche l’approvazione specifica delle clausole per i clienti professionali.' };
        return;
      }
      if (clientType === 'consumer' && declarations.earlyStartRequested === true && declarations.earlyStartAcknowledged !== true) {
        outcome = { status: 400, error: 'Per chiedere l’avvio anticipato devi confermare anche la relativa dichiarazione.' };
        return;
      }
    }
    const auditPayload = {
      eventId,
      decision,
      quoteId: id,
      quoteNumber: clean(quote.quoteNumber, 80),
      quoteHash: clean(quote.quoteHash, 128),
      clientEmailHash: hashHex(String(quote.client?.email || '').trim().toLowerCase()),
      customerName,
      requestTimeIso,
      ipHash: hashHex(ip),
      userAgent,
      verificationMethod: 'email_otp',
      verificationId,
      termsVersion: clean(quote.termsVersion, 60),
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
    outcome = {
      status: 200,
      success: true,
      decision,
      eventId,
      auditHash,
      requestTimeIso,
      quoteNumber: clean(quote.quoteNumber, 80),
      customerName
    };
  });
  if (!outcome) return json(res, 500, { error: 'Non è stato possibile registrare la risposta.' });
  if (outcome.error) return json(res, outcome.status, { error: outcome.error });
  return json(res, 200, outcome);
}

function publicQuoteData(id, quote) {
  const client = isPlainObject(quote.client) ? quote.client : {};
  const acceptance = isPlainObject(quote.acceptance) ? quote.acceptance : null;
  const rejection = isPlainObject(quote.rejection) ? quote.rejection : null;
  let document = null;
  if (isPlainObject(quote.document)) {
    const safeFields = sanitizeData(quote.document.fields, 0, 50) || {};
    delete safeFields.clientEmail;
    delete safeFields.email;
    delete safeFields.ip;
    delete safeFields.ipHash;
    document = {
      fields: safeFields,
      items: sanitizeData(quote.document.items, 0, 100) || [],
      itemPricing: quote.document.itemPricing === true,
      provider: sanitizeData(quote.document.provider, 0, 30) || {},
      legal: sanitizeData(quote.document.legal, 0, 30) || {},
      recurringPriceCents: Number.isSafeInteger(quote.document.recurringPriceCents) && quote.document.recurringPriceCents >= 0
        ? quote.document.recurringPriceCents
        : null
    };
  }
  const rawTotal = Number(quote.totalCents);
  const safeTotalCents = Number.isSafeInteger(rawTotal) && rawTotal >= 0 && rawTotal <= 100000000000 ? rawTotal : 0;
  const currency = ALLOWED_CURRENCIES.has(quote.currency) ? quote.currency : 'EUR';
  const clientType = ALLOWED_CLIENT_TYPES.has(client.type) ? client.type : 'consumer';
  const status = ALLOWED_STATUSES.has(quote.status) ? quote.status : 'pending';
  const rawTermsUrl = typeof quote.termsUrl === 'string' ? quote.termsUrl.trim() : '';
  const termsUrl = /^https:\/\/(www\.)?creatorweb\.cc\//.test(rawTermsUrl)
    ? clean(rawTermsUrl, 300)
    : 'https://www.creatorweb.cc/termini.html';
  return {
    id,
    quoteNumber: clean(quote.quoteNumber, 80),
    client: {
      name: clean(client.name, 160),
      type: clientType,
      address: clean(client.address, 300),
      emailMasked: maskEmail(client.email || '')
    },
    project: sanitizeData(quote.project, 0, 50) || {},
    items: sanitizeData(quote.items, 0, 100) || [],
    totalCents: safeTotalCents,
    currency,
    document,
    terms: sanitizeData(quote.terms, 0, 50) || {},
    termsVersion: clean(quote.termsVersion, 60),
    termsUrl,
    status,
    createdAt: serializeDate(quote.createdAt, quote.createdAtIso),
    validUntil: serializeDate(quote.validUntil, quote.validUntilIso),
    expired: isExpired(quote),
    acceptance: acceptance ? {
      eventId: clean(acceptance.eventId, 64),
      customerName: clean(acceptance.customerName, 160),
      requestTimeIso: serializeDate(acceptance.requestTimeIso, null),
      auditHash: clean(acceptance.auditHash, 128)
    } : null,
    rejection: rejection ? {
      eventId: clean(rejection.eventId, 64),
      customerName: clean(rejection.customerName, 160),
      requestTimeIso: serializeDate(rejection.requestTimeIso, null),
      auditHash: clean(rejection.auditHash, 128)
    } : null
  };
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  const origin = typeof req.headers.origin === 'string' ? req.headers.origin.trim() : '';
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json(res, 403, { error: 'Origine non autorizzata.' });
  }
  const ip = getClientIp(req);
  try {
    if (req.method === 'GET') {
      const id = clean(typeof req.query?.id === 'string' ? req.query.id : '', 100).toLowerCase();
      if (!validId(id)) return json(res, 400, { error: 'Link del preventivo non valido o incompleto.' });
      const snapshot = await getQuoteRef(id).get();
      if (!snapshot.exists) return json(res, 404, { error: 'Preventivo non trovato. Verifica il link ricevuto.' });
      const quote = snapshot.data() || {};
      return json(res, 200, { quote: publicQuoteData(id, quote) });
    }
    if (req.method !== 'POST') return json(res, 405, { error: 'Metodo non consentito.' });
    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    if (!contentType.includes('application/json')) {
      return json(res, 415, { error: 'Content-Type non supportato.' });
    }
    const body = parseJsonBody(req);
    const id = clean(typeof body.id === 'string' ? body.id : '', 100).toLowerCase();
    if (!validId(id)) return json(res, 400, { error: 'Link del preventivo non valido o incompleto.' });
    const action = clean(typeof body.action === 'string' ? body.action : '', 40);
    if (action === 'request_otp') return await requestOtp(req, res, id, ip);
    if (action === 'accept') return await registerDecision(req, res, id, body, ip, 'accepted');
    if (action === 'reject') return await registerDecision(req, res, id, body, ip, 'rejected');
    return json(res, 400, { error: 'Operazione non riconosciuta.' });
  } catch (error) {
    if (error && error.expose && Number.isInteger(error.status)) {
      return json(res, error.status, { error: error.message });
    }
    return json(res, 500, { error: 'Errore interno del server.' });
  }
};

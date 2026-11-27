'use strict';

const crypto = require('crypto');
const {
    admin,
    db,
    stripe,
    SITE_URL,
    setCors,
    rejectOrigin,
    requireCustomer,
    getOrCreateStripeCustomer,
    planPriceConfig,
    retrieveUsableSubscriptionPrice
} = require('../lib/stripe');

const rateLimits = new Map();
const WINDOW_MS = 60000;
const MAX_REQUESTS_PER_WINDOW = 15;
const LOCK_TTL_MS = 120000;
const ALLOWED_SLOT_PATHS = new Set([
    'pagamenti.progetto.rate.rata_1',
    'pagamenti.progetto.rate.rata_2',
    'pagamenti.progetto.rate.rata_3',
    'pagamenti.abbonamento'
]);

function pruneExpiredRateLimits(now) {
    if (rateLimits.size < 500) return;
    for (const [key, entry] of rateLimits.entries()) {
        if (now - entry.startedAt > WINDOW_MS) {
            rateLimits.delete(key);
        }
    }
}

function getClientKey(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const rawIp = (typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : '')
        || req.socket?.remoteAddress
        || 'unknown';
    const ip = rawIp.slice(0, 64);
    const authHeader = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
    if (!authHeader) return `ip:${ip}`;
    const authHash = crypto.createHash('sha256').update(authHeader).digest('hex').slice(0, 16);
    return `ip:${ip}:auth:${authHash}`;
}

function rateLimited(req) {
    const now = Date.now();
    pruneExpiredRateLimits(now);
    const key = getClientKey(req);
    const current = rateLimits.get(key) || { count: 0, startedAt: now };
    if (now - current.startedAt > WINDOW_MS) {
        current.count = 0;
        current.startedAt = now;
    }
    current.count += 1;
    rateLimits.set(key, current);
    return current.count > MAX_REQUESTS_PER_WINDOW;
}

function createHttpError(status, message, code) {
    const error = new Error(message);
    error.status = status;
    if (code) error.code = code;
    return error;
}

function assertValidSlotPath(slotPath) {
    if (typeof slotPath !== 'string' || !ALLOWED_SLOT_PATHS.has(slotPath)) {
        throw createHttpError(400, 'Percorso di pagamento non valido.');
    }
}

function assertValidSessionId(sessionId) {
    if (typeof sessionId !== 'string') return null;
    const trimmed = sessionId.trim();
    if (!/^cs_(test|live)_[A-Za-z0-9_]+$/.test(trimmed)) return null;
    return trimmed;
}

async function getReusableSession(rawSessionId, expectedCustomerId) {
    const sessionId = assertValidSessionId(rawSessionId);
    if (!sessionId) return null;
    try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        if (!session || typeof session !== 'object') return null;
        if (expectedCustomerId && session.customer && session.customer !== expectedCustomerId) {
            return null;
        }
        if (session.status === 'open' && typeof session.url === 'string' && session.url.startsWith('https://')) {
            return { url: session.url, sessionId: session.id, reused: true };
        }
        if (session.payment_status === 'paid' || session.status === 'complete') {
            return { completed: true, sessionId: session.id };
        }
    } catch (error) {
        if (error && error.code !== 'resource_missing') {
            throw createHttpError(502, 'Errore di comunicazione con il servizio di pagamento.');
        }
    }
    return null;
}

function readNested(object, dottedPath) {
    if (!object || typeof object !== 'object') return undefined;
    return dottedPath.split('.').reduce((value, key) => {
        if (!value || typeof value !== 'object' || !Object.prototype.hasOwnProperty.call(value, key)) {
            return undefined;
        }
        return value[key];
    }, object);
}

function timestampMillis(value) {
    if (!value) return 0;
    if (typeof value.toMillis === 'function') return value.toMillis();
    const parsed = value instanceof Date ? value.getTime() : new Date(value).getTime();
    return Number.isFinite(parsed) ? parsed : 0;
}

async function reserveCheckoutSlot(uid, slotPath, staleSessionId) {
    assertValidSlotPath(slotPath);
    const profileRef = db.collection('utenti_dashboard').doc(uid);
    const attemptId = crypto.randomUUID();
    const now = Date.now();
    return db.runTransaction(async transaction => {
        const snapshot = await transaction.get(profileRef);
        if (!snapshot.exists) {
            throw createHttpError(404, 'Profilo cliente non trovato.');
        }
        const profile = snapshot.data() || {};
        const slot = readNested(profile, slotPath) || {};
        if (slot.stato === 'paid') {
            throw createHttpError(409, 'Questo pagamento risulta già effettuato.');
        }
        const currentSessionId = assertValidSessionId(slot.checkout_session_id);
        const normalizedStale = assertValidSessionId(staleSessionId);
        if (currentSessionId && currentSessionId !== normalizedStale) {
            return { existingSessionId: currentSessionId };
        }
        const lockExpiresAt = timestampMillis(slot.checkout_lock_expires_at);
        if (slot.checkout_lock_id && lockExpiresAt > now) {
            throw createHttpError(409, 'Un pagamento è già in preparazione. Attendi qualche secondo e riprova.');
        }
        transaction.update(profileRef, {
            [`${slotPath}.checkout_lock_id`]: attemptId,
            [`${slotPath}.checkout_lock_expires_at`]: new Date(now + LOCK_TTL_MS)
        });
        return { attemptId };
    });
}

async function persistCheckoutSlot(uid, slotPath, attemptId, session) {
    assertValidSlotPath(slotPath);
    const profileRef = db.collection('utenti_dashboard').doc(uid);
    return db.runTransaction(async transaction => {
        const snapshot = await transaction.get(profileRef);
        if (!snapshot.exists) return false;
        const slot = readNested(snapshot.data() || {}, slotPath) || {};
        if (slot.checkout_lock_id !== attemptId || slot.stato === 'paid') return false;
        transaction.update(profileRef, {
            [`${slotPath}.stato`]: 'checkout_pending',
            [`${slotPath}.checkout_session_id`]: session.id,
            [`${slotPath}.checkout_created_at`]: new Date(),
            [`${slotPath}.checkout_lock_id`]: admin.firestore.FieldValue.delete(),
            [`${slotPath}.checkout_lock_expires_at`]: admin.firestore.FieldValue.delete()
        });
        return true;
    });
}

async function releaseCheckoutSlot(uid, slotPath, attemptId) {
    assertValidSlotPath(slotPath);
    const profileRef = db.collection('utenti_dashboard').doc(uid);
    await db.runTransaction(async transaction => {
        const snapshot = await transaction.get(profileRef);
        if (!snapshot.exists) return;
        const slot = readNested(snapshot.data() || {}, slotPath) || {};
        if (slot.checkout_lock_id !== attemptId) return;
        transaction.update(profileRef, {
            [`${slotPath}.checkout_lock_id`]: admin.firestore.FieldValue.delete(),
            [`${slotPath}.checkout_lock_expires_at`]: admin.firestore.FieldValue.delete()
        });
    });
}

async function acquireCheckoutSlot(uid, slotPath, staleSessionId, expectedCustomerId) {
    let reservation = await reserveCheckoutSlot(uid, slotPath, staleSessionId);
    if (!reservation.existingSessionId) return reservation;
    const existing = await getReusableSession(reservation.existingSessionId, expectedCustomerId);
    if (existing?.url) return { existing };
    if (existing?.completed) {
        throw createHttpError(409, 'Il pagamento è già stato completato. Attendi l’aggiornamento dello stato.');
    }
    reservation = await reserveCheckoutSlot(uid, slotPath, reservation.existingSessionId);
    if (reservation.existingSessionId) {
        throw createHttpError(409, 'È già presente un altro pagamento. Aggiorna la dashboard e riprova.');
    }
    return reservation;
}

function parseInstallmentNumber(rawInstallment) {
    if (typeof rawInstallment === 'number') {
        return Number.isInteger(rawInstallment) && [1, 2, 3].includes(rawInstallment) ? rawInstallment : null;
    }
    if (typeof rawInstallment === 'string' && /^[123]$/.test(rawInstallment.trim())) {
        return Number(rawInstallment.trim());
    }
    return null;
}

async function createProjectInstallmentCheckout(uid, profile, rawInstallment) {
    const installmentNumber = parseInstallmentNumber(rawInstallment);
    if (!installmentNumber) {
        throw createHttpError(400, 'Rata non valida.');
    }
    const project = profile.pagamenti?.progetto || {};
    const totalCents = Number(project.totale_cent);
    const phase = Number(project.fase);
    const rateKey = `rata_${installmentNumber}`;
    const rate = project.rate?.[rateKey] || {};
    const amountCents = Number(rate.importo_cent);
    if (!Number.isSafeInteger(totalCents) || totalCents <= 0 || !Number.isSafeInteger(amountCents) || amountCents <= 0) {
        throw createHttpError(409, 'Il totale del progetto non è ancora stato configurato dall’amministratore.');
    }
    if (rate.stato === 'paid') {
        throw createHttpError(409, 'Questa rata risulta già pagata.');
    }
    if (!Number.isFinite(phase) || phase < installmentNumber || !['unlocked', 'checkout_pending'].includes(rate.stato)) {
        throw createHttpError(403, 'Questa rata non è ancora stata sbloccata dall’amministratore.');
    }
    const first = Math.round(totalCents * 0.20);
    const second = Math.round(totalCents * 0.60);
    const third = totalCents - first - second;
    const expectedAmounts = [first, second, third];
    const expectedAmount = expectedAmounts[installmentNumber - 1];
    if (!Number.isSafeInteger(expectedAmount) || expectedAmount <= 0 || amountCents !== expectedAmount) {
        throw createHttpError(409, 'Configurazione della rata non coerente con il totale del progetto. Contatta l’amministratore.');
    }
    const slotPath = `pagamenti.progetto.rate.${rateKey}`;
    const expectedCustomerId = typeof profile.stripe_customer_id === 'string' ? profile.stripe_customer_id : null;
    const reservation = await acquireCheckoutSlot(uid, slotPath, rate.checkout_session_id || null, expectedCustomerId);
    if (reservation.existing) return reservation.existing;
    const attemptId = reservation.attemptId;
    try {
        const customer = await getOrCreateStripeCustomer(uid, profile);
        if (!customer?.id || typeof customer.id !== 'string') {
            throw createHttpError(502, 'Impossibile inizializzare il profilo di fatturazione.');
        }
        const descriptions = {
            1: 'Avvio progetto — prima rata (20%)',
            2: 'Sviluppo progetto — seconda rata (60%)',
            3: 'Consegna progetto — terza rata (20%)'
        };
        const metadata = {
            userid: uid,
            payment_type: 'project_installment',
            installment_number: String(installmentNumber),
            project_total_cents: String(totalCents)
        };
        const session = await stripe.checkout.sessions.create({
            mode: 'payment',
            customer: customer.id,
            client_reference_id: uid,
            line_items: [{
                quantity: 1,
                price_data: {
                    currency: 'eur',
                    unit_amount: expectedAmount,
                    product_data: {
                        name: `CreatorWeb — ${descriptions[installmentNumber]}`
                    }
                }
            }],
            invoice_creation: { enabled: true },
            payment_intent_data: {
                description: `CreatorWeb — ${descriptions[installmentNumber]}`,
                metadata
            },
            metadata,
            success_url: `${SITE_URL}/dashboard.html?pagamento=successo&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${SITE_URL}/dashboard.html?pagamento=annullato`
        }, {
            idempotencyKey: `creatorweb-${uid}-rata-${installmentNumber}-${attemptId}`
        });
        if (!session?.id || typeof session.url !== 'string' || !session.url.startsWith('https://')) {
            throw createHttpError(502, 'Stripe non ha restituito un URL di pagamento valido.');
        }
        const saved = await persistCheckoutSlot(uid, slotPath, attemptId, session);
        if (!saved) {
            throw createHttpError(409, 'Il pagamento è stato creato ma la sessione non è stata collegata al profilo. Contatta l’assistenza prima di riprovare.');
        }
        return { url: session.url, sessionId: session.id, reused: false };
    } catch (error) {
        await releaseCheckoutSlot(uid, slotPath, attemptId).catch(() => {});
        throw error;
    }
}

async function createSubscriptionCheckout(uid, profile) {
    const payments = profile.pagamenti || {};
    const project = payments.progetto || {};
    const subscription = payments.abbonamento || {};
    if (Number(project.fase) !== 3) {
        throw createHttpError(403, 'L’abbonamento potrà essere attivato dopo la fase 3 del progetto.');
    }
    if (subscription.attivazione_abilitata !== true) {
        throw createHttpError(403, 'L’amministratore non ha ancora abilitato l’attivazione dell’abbonamento.');
    }
    if (project.rate?.rata_3?.stato !== 'paid') {
        throw createHttpError(409, 'Prima di attivare l’abbonamento deve risultare pagata anche la rata finale del progetto.');
    }
    const status = String(subscription.stato || '').toLowerCase();
    if (['active', 'trialing', 'past_due', 'unpaid', 'incomplete'].includes(status)) {
        throw createHttpError(409, 'Esiste già un abbonamento o un’attivazione in corso. Usa il portale Stripe per gestirlo.');
    }
    const slotPath = 'pagamenti.abbonamento';
    const expectedCustomerId = typeof profile.stripe_customer_id === 'string' ? profile.stripe_customer_id : null;
    const reservation = await acquireCheckoutSlot(uid, slotPath, subscription.checkout_session_id || null, expectedCustomerId);
    if (reservation.existing) return reservation.existing;
    const attemptId = reservation.attemptId;
    try {
        const planConfig = planPriceConfig(subscription.piano_scelto);
        const price = await retrieveUsableSubscriptionPrice(planConfig);
        const customer = await getOrCreateStripeCustomer(uid, profile);
        if (!customer?.id || typeof customer.id !== 'string' || !price?.id) {
            throw createHttpError(502, 'Configurazione del piano o del cliente non valida.');
        }
        const metadata = {
            userid: uid,
            payment_type: 'subscription',
            plan: planConfig.key
        };
        const session = await stripe.checkout.sessions.create({
            mode: 'subscription',
            customer: customer.id,
            client_reference_id: uid,
            line_items: [{ price: price.id, quantity: 1 }],
            subscription_data: { metadata },
            metadata,
            success_url: `${SITE_URL}/dashboard.html?abbonamento=successo&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${SITE_URL}/dashboard.html?abbonamento=annullato`
        }, {
            idempotencyKey: `creatorweb-${uid}-subscription-${attemptId}`
        });
        if (!session?.id || typeof session.url !== 'string' || !session.url.startsWith('https://')) {
            throw createHttpError(502, 'Stripe non ha restituito un URL di pagamento valido.');
        }
        const saved = await persistCheckoutSlot(uid, slotPath, attemptId, session);
        if (!saved) {
            throw createHttpError(409, 'La sessione di attivazione non è stata collegata al profilo. Contatta l’assistenza prima di riprovare.');
        }
        return { url: session.url, sessionId: session.id, reused: false };
    } catch (error) {
        await releaseCheckoutSlot(uid, slotPath, attemptId).catch(() => {});
        throw error;
    }
}

module.exports = async function handler(req, res) {
    setCors(req, res);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    if (req.method === 'OPTIONS') return res.status(204).end();
    if (rejectOrigin(req)) return res.status(403).json({ error: 'Origin non autorizzata.' });
    if (req.method !== 'POST') return res.status(405).json({ error: 'Metodo non consentito.' });
    if (rateLimited(req)) return res.status(429).json({ error: 'Troppe richieste. Riprova tra un minuto.' });
    try {
        const { uid, profile } = await requireCustomer(req);
        if (!uid || typeof uid !== 'string' || !profile || typeof profile !== 'object') {
            throw createHttpError(401, 'Sessione utente non valida.');
        }
        const rawBody = req.body;
        if (!rawBody || typeof rawBody !== 'object' || Array.isArray(rawBody)) {
            return res.status(400).json({ error: 'Corpo della richiesta non valido.' });
        }
        const type = typeof rawBody.type === 'string' ? rawBody.type.trim() : '';
        let result;
        if (type === 'project_installment') {
            result = await createProjectInstallmentCheckout(uid, profile, rawBody.installment);
        } else if (type === 'subscription') {
            result = await createSubscriptionCheckout(uid, profile);
        } else {
            return res.status(400).json({ error: 'Tipo di pagamento non riconosciuto.' });
        }
        if (!result?.url) {
            return res.status(500).json({ error: 'Stripe non ha restituito un URL di pagamento.' });
        }
        return res.status(200).json({ success: true, url: result.url, reused: Boolean(result.reused) });
    } catch (error) {
        const status = Number.isInteger(error?.status) && error.status >= 400 && error.status < 600
            ? error.status
            : 500;
        const payload = {
            error: status < 500 && error?.message
                ? error.message
                : 'Non è stato possibile creare il pagamento Stripe.'
        };
        if (status < 500 && typeof error?.code === 'string' && error.code.length <= 40) {
            payload.code = error.code;
        }
        return res.status(status).json(payload);
    }
};

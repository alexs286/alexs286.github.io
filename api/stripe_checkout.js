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

function rateLimited(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = (typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : '')
        || req.socket?.remoteAddress
        || 'unknown';
    const now = Date.now();
    const current = rateLimits.get(ip) || { count: 0, startedAt: now };
    if (now - current.startedAt > 60000) {
        current.count = 0;
        current.startedAt = now;
    }
    current.count += 1;
    rateLimits.set(ip, current);
    return current.count > 15;
}

async function getReusableSession(sessionId) {
    if (!sessionId) return null;
    try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        if (session.status === 'open' && session.url) {
            return { url: session.url, sessionId: session.id, reused: true };
        }
        if (session.payment_status === 'paid' || session.status === 'complete') {
            return { completed: true, sessionId: session.id };
        }
    } catch (error) {
        if (error.code !== 'resource_missing') throw error;
    }
    return null;
}

function readNested(object, dottedPath) {
    return dottedPath.split('.').reduce((value, key) => value?.[key], object);
}

function timestampMillis(value) {
    if (!value) return 0;
    if (typeof value.toMillis === 'function') return value.toMillis();
    const parsed = value instanceof Date ? value.getTime() : new Date(value).getTime();
    return Number.isFinite(parsed) ? parsed : 0;
}

async function reserveCheckoutSlot(uid, slotPath, staleSessionId) {
    const profileRef = db.collection('utenti_dashboard').doc(uid);
    const attemptId = crypto.randomUUID();
    return db.runTransaction(async transaction => {
        const snapshot = await transaction.get(profileRef);
        if (!snapshot.exists) {
            const error = new Error('Profilo cliente non trovato.');
            error.status = 404;
            throw error;
        }
        const profile = snapshot.data() || {};
        const slot = readNested(profile, slotPath) || {};
        if (slot.stato === 'paid') {
            const error = new Error('Questo pagamento risulta già effettuato.');
            error.status = 409;
            throw error;
        }

        const currentSessionId = slot.checkout_session_id || null;
        if (currentSessionId && currentSessionId !== staleSessionId) {
            return { existingSessionId: currentSessionId };
        }

        const lockExpiresAt = timestampMillis(slot.checkout_lock_expires_at);
        if (slot.checkout_lock_id && lockExpiresAt > Date.now()) {
            const error = new Error('Un pagamento è già in preparazione. Attendi qualche secondo e riprova.');
            error.status = 409;
            throw error;
        }

        transaction.update(profileRef, {
            [`${slotPath}.checkout_lock_id`]: attemptId,
            [`${slotPath}.checkout_lock_expires_at`]: new Date(Date.now() + 120000)
        });
        return { attemptId };
    });
}

async function persistCheckoutSlot(uid, slotPath, attemptId, session) {
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

async function acquireCheckoutSlot(uid, slotPath, staleSessionId) {
    let reservation = await reserveCheckoutSlot(uid, slotPath, staleSessionId);
    if (!reservation.existingSessionId) return reservation;

    const existing = await getReusableSession(reservation.existingSessionId);
    if (existing?.url) return { existing };
    if (existing?.completed) {
        const error = new Error('Il pagamento è già stato completato. Attendi l’aggiornamento dello stato.');
        error.status = 409;
        throw error;
    }

    reservation = await reserveCheckoutSlot(uid, slotPath, reservation.existingSessionId);
    if (reservation.existingSessionId) {
        const error = new Error('È già presente un altro pagamento. Aggiorna la dashboard e riprova.');
        error.status = 409;
        throw error;
    }
    return reservation;
}

async function createProjectInstallmentCheckout(uid, profile, installmentNumber) {
    if (![1, 2, 3].includes(installmentNumber)) {
        const error = new Error('Rata non valida.');
        error.status = 400;
        throw error;
    }

    const project = profile.pagamenti?.progetto || {};
    const totalCents = Number(project.totale_cent || 0);
    const phase = Number(project.fase || 0);
    const rateKey = `rata_${installmentNumber}`;
    const rate = project.rate?.[rateKey] || {};
    const amountCents = Number(rate.importo_cent || 0);

    if (!Number.isSafeInteger(totalCents) || totalCents <= 0 || !Number.isSafeInteger(amountCents) || amountCents <= 0) {
        const error = new Error('Il totale del progetto non è ancora stato configurato dall’amministratore.');
        error.status = 409;
        throw error;
    }
    if (rate.stato === 'paid') {
        const error = new Error('Questa rata risulta già pagata.');
        error.status = 409;
        throw error;
    }
    if (phase < installmentNumber || !['unlocked', 'checkout_pending'].includes(rate.stato)) {
        const error = new Error('Questa rata non è ancora stata sbloccata dall’amministratore.');
        error.status = 403;
        throw error;
    }

    const expectedAmounts = [
        Math.round(totalCents * 0.20),
        Math.round(totalCents * 0.60),
        totalCents - Math.round(totalCents * 0.20) - Math.round(totalCents * 0.60)
    ];
    const expectedAmount = expectedAmounts[installmentNumber - 1];
    if (amountCents !== expectedAmount || expectedAmount <= 0) {
        const error = new Error('Configurazione della rata non coerente con il totale del progetto. Contatta l’amministratore.');
        error.status = 409;
        throw error;
    }

    const slotPath = `pagamenti.progetto.rate.${rateKey}`;
    const reservation = await acquireCheckoutSlot(uid, slotPath, rate.checkout_session_id || null);
    if (reservation.existing) return reservation.existing;
    const attemptId = reservation.attemptId;

    try {
        const customer = await getOrCreateStripeCustomer(uid, profile);
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

        const saved = await persistCheckoutSlot(uid, slotPath, attemptId, session);
        if (!saved) {
            const error = new Error('Il pagamento è stato creato ma la sessione non è stata collegata al profilo. Contatta l’assistenza prima di riprovare.');
            error.status = 409;
            throw error;
        }

        return { url: session.url, sessionId: session.id, reused: false };
    } catch (error) {
        await releaseCheckoutSlot(uid, slotPath, attemptId).catch(releaseError => console.error('Checkout lock release failed:', releaseError));
        throw error;
    }
}

async function createSubscriptionCheckout(uid, profile) {
    const payments = profile.pagamenti || {};
    const project = payments.progetto || {};
    const subscription = payments.abbonamento || {};

    if (Number(project.fase || 0) !== 3) {
        const error = new Error('L’abbonamento potrà essere attivato dopo la fase 3 del progetto.');
        error.status = 403;
        throw error;
    }
    if (subscription.attivazione_abilitata !== true) {
        const error = new Error('L’amministratore non ha ancora abilitato l’attivazione dell’abbonamento.');
        error.status = 403;
        throw error;
    }
    if (project.rate?.rata_3?.stato !== 'paid') {
        const error = new Error('Prima di attivare l’abbonamento deve risultare pagata anche la rata finale del progetto.');
        error.status = 409;
        throw error;
    }

    const status = String(subscription.stato || '').toLowerCase();
    if (['active', 'trialing', 'past_due', 'unpaid', 'incomplete'].includes(status)) {
        const error = new Error('Esiste già un abbonamento o un’attivazione in corso. Usa il portale Stripe per gestirlo.');
        error.status = 409;
        throw error;
    }

    const slotPath = 'pagamenti.abbonamento';
    const reservation = await acquireCheckoutSlot(uid, slotPath, subscription.checkout_session_id || null);
    if (reservation.existing) return reservation.existing;
    const attemptId = reservation.attemptId;

    try {
        const planConfig = planPriceConfig(subscription.piano_scelto);
        const price = await retrieveUsableSubscriptionPrice(planConfig);
        const customer = await getOrCreateStripeCustomer(uid, profile);
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

        const saved = await persistCheckoutSlot(uid, slotPath, attemptId, session);
        if (!saved) {
            const error = new Error('La sessione di attivazione non è stata collegata al profilo. Contatta l’assistenza prima di riprovare.');
            error.status = 409;
            throw error;
        }

        return { url: session.url, sessionId: session.id, reused: false };
    } catch (error) {
        await releaseCheckoutSlot(uid, slotPath, attemptId).catch(releaseError => console.error('Checkout lock release failed:', releaseError));
        throw error;
    }
}

module.exports = async function handler(req, res) {
    setCors(req, res);
    if (req.method === 'OPTIONS') return res.status(204).end();
    if (rejectOrigin(req)) return res.status(403).json({ error: 'Origin non autorizzata.' });
    if (req.method !== 'POST') return res.status(405).json({ error: 'Metodo non consentito.' });
    if (rateLimited(req)) return res.status(429).json({ error: 'Troppe richieste. Riprova tra un minuto.' });

    try {
        const { uid, profile } = await requireCustomer(req);
        const body = req.body && typeof req.body === 'object' ? req.body : {};
        const type = String(body.type || '').trim();

        let result;
        if (type === 'project_installment') {
            result = await createProjectInstallmentCheckout(uid, profile, Number(body.installment));
        } else if (type === 'subscription') {
            result = await createSubscriptionCheckout(uid, profile);
        } else {
            return res.status(400).json({ error: 'Tipo di pagamento non riconosciuto.' });
        }

        if (!result.url) return res.status(500).json({ error: 'Stripe non ha restituito un URL di pagamento.' });
        return res.status(200).json({ success: true, url: result.url, reused: Boolean(result.reused) });
    } catch (error) {
        if (!error.status) console.error('Stripe Checkout API error:', error);
        return res.status(error.status || 500).json({
            error: error.status ? error.message : 'Non è stato possibile creare il pagamento Stripe.',
            code: error.code || undefined
        });
    }
};

'use strict';

const { admin, db, stripe } = require('../lib/stripe');

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
if (!WEBHOOK_SECRET) throw new Error('Missing STRIPE_WEBHOOK_SECRET');

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_MIGRATION_HOPS = 5;
const ALLOWED_PLANS = new Set(['base', 'standard', 'premium']);
const STRIPE_SUBSCRIPTION_STATUSES = new Set([
    'incomplete', 'incomplete_expired', 'trialing', 'active',
    'past_due', 'canceled', 'unpaid', 'paused'
]);
const ALLOWED_EVENT_TYPES = new Set([
    'checkout.session.completed',
    'checkout.session.async_payment_succeeded',
    'checkout.session.async_payment_failed',
    'checkout.session.expired',
    'customer.subscription.created',
    'customer.subscription.updated',
    'customer.subscription.deleted',
    'customer.subscription.paused',
    'customer.subscription.resumed',
    'customer.subscription.pending_update_applied',
    'customer.subscription.pending_update_expired',
    'customer.subscription.trial_will_end',
    'invoice.paid',
    'invoice.payment_failed',
    'payout.paid',
    'payout.failed',
    'payout.canceled',
    'payout.created',
    'payout.updated',
    'payout.reconciliation_completed'
]);

function isSafeDocId(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 255 && !value.includes('/');
}

function getId(value) {
    if (!value) return null;
    const id = typeof value === 'string' ? value : (typeof value.id === 'string' ? value.id : null);
    return isSafeDocId(id) ? id : null;
}

function unixToDate(value) {
    return typeof value === 'number' && Number.isFinite(value) ? new Date(value * 1000) : null;
}

function cleanObject(obj, depth = 0) {
    if (depth > 25 || obj === null || obj === undefined) return null;
    if (typeof obj === 'string' || typeof obj === 'boolean') return obj;
    if (typeof obj === 'number') return Number.isFinite(obj) ? obj : null;
    if (Array.isArray(obj)) {
        return obj.slice(0, 200).map(item => cleanObject(item, depth + 1));
    }
    if (typeof obj === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(obj)) {
            if (typeof k !== 'string' || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
            if (typeof v === 'function' || typeof v === 'symbol' || typeof v === 'undefined') continue;
            out[k] = cleanObject(v, depth + 1);
        }
        return out;
    }
    return null;
}

function createHttpError(message, status) {
    const err = new Error(message);
    err.status = status;
    return err;
}

async function readRawRequestBody(req) {
    const contentLength = Number(req.headers?.['content-length']);
    if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
        throw createHttpError('Webhook body too large', 413);
    }

    if (Buffer.isBuffer(req.rawBody)) {
        if (req.rawBody.length > MAX_BODY_BYTES) throw createHttpError('Webhook body too large', 413);
        if (!req.rawBody.length) throw createHttpError('Raw webhook body is empty', 400);
        return req.rawBody;
    }

    if (typeof req.rawBody === 'string') {
        const buf = Buffer.from(req.rawBody, 'utf8');
        if (buf.length > MAX_BODY_BYTES) throw createHttpError('Webhook body too large', 413);
        if (!buf.length) throw createHttpError('Raw webhook body is empty', 400);
        return buf;
    }

    const chunks = [];
    let totalBytes = 0;
    for await (const chunk of req) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += buffer.length;
        if (totalBytes > MAX_BODY_BYTES) {
            throw createHttpError('Webhook body too large', 413);
        }
        chunks.push(buffer);
    }

    if (!totalBytes) {
        throw createHttpError('Raw webhook body is empty', 400);
    }
    return Buffer.concat(chunks, totalBytes);
}

async function resolveMigratedUserId(userId) {
    if (!isSafeDocId(userId)) return null;
    let currentId = userId;
    const seen = new Set([currentId]);

    for (let i = 0; i < MAX_MIGRATION_HOPS; i++) {
        const snap = await db.collection('utenti_dashboard').doc(currentId).get();
        if (!snap.exists) break;
        const nextId = snap.data()?.migrated_to_uid;
        if (!isSafeDocId(nextId) || seen.has(nextId)) break;
        seen.add(nextId);
        currentId = nextId;
    }
    return currentId;
}

async function findUserId(event, obj) {
    const metadata = obj?.metadata || obj?.parent?.subscription_details?.metadata || {};
    const rawMetaId = typeof metadata.userid === 'string' && metadata.userid
        ? metadata.userid
        : (typeof metadata.userId === 'string' && metadata.userId
            ? metadata.userId
            : (typeof obj?.client_reference_id === 'string' ? obj.client_reference_id : null));

    if (rawMetaId) {
        const resolved = await resolveMigratedUserId(rawMetaId);
        if (resolved) return resolved;
    }

    const accountId = getId(event.account);
    if (accountId) {
        const accountDoc = await db.collection('stripeAccounts').doc(accountId).get();
        if (accountDoc.exists && isSafeDocId(accountDoc.data()?.userid)) {
            return resolveMigratedUserId(accountDoc.data().userid);
        }
    }

    const customerId = getId(obj.customer);
    if (customerId) {
        const customerDoc = await db.collection('stripeCustomers').doc(customerId).get();
        if (customerDoc.exists && isSafeDocId(customerDoc.data()?.userid)) {
            return resolveMigratedUserId(customerDoc.data().userid);
        }
    }

    let subscriptionId = getId(obj.subscription) || getId(obj.parent?.subscription_details?.subscription);
    if (!subscriptionId && obj.object === 'subscription') subscriptionId = getId(obj.id);

    if (subscriptionId) {
        const subscriptionDoc = await db.collection('stripeSubscriptions').doc(subscriptionId).get();
        if (subscriptionDoc.exists && isSafeDocId(subscriptionDoc.data()?.userid)) {
            return resolveMigratedUserId(subscriptionDoc.data().userid);
        }
    }

    return null;
}

async function saveStripeMappings(userid, obj, event) {
    if (!isSafeDocId(userid)) return;
    const batch = db.batch();
    const customerId = getId(obj.customer);
    const subscriptionId = getId(obj.subscription)
        || (obj.object === 'subscription' ? getId(obj.id) : null)
        || getId(obj.parent?.subscription_details?.subscription);
    const accountId = getId(event.account) || (obj.object === 'account' ? getId(obj.id) : null);

    let hasOps = false;
    if (customerId) {
        batch.set(db.collection('stripeCustomers').doc(customerId), { userid }, { merge: true });
        hasOps = true;
    }
    if (subscriptionId) {
        batch.set(db.collection('stripeSubscriptions').doc(subscriptionId), { userid }, { merge: true });
        hasOps = true;
    }
    if (accountId) {
        batch.set(db.collection('stripeAccounts').doc(accountId), { userid }, { merge: true });
        hasOps = true;
    }
    if (hasOps) await batch.commit();
}

function extractStripeData(event) {
    const obj = event.data.object;
    const data = {
        last_event_id: event.id,
        last_event_type: event.type,
        last_event_created: unixToDate(event.created),
        last_event_received_at: admin.firestore.FieldValue.serverTimestamp()
    };

    if (event.type.startsWith('checkout.session.')) {
        data.checkout_session_id = getId(obj.id);
        data.checkout_status = typeof obj.status === 'string' ? obj.status : null;
        data.payment_status = typeof obj.payment_status === 'string' ? obj.payment_status : null;
        data.customer_id = getId(obj.customer);
        data.subscription_id = getId(obj.subscription);
        data.checkout_mode = typeof obj.mode === 'string' ? obj.mode : null;
        data.checkout_amount_total = typeof obj.amount_total === 'number' ? obj.amount_total : null;
        data.checkout_currency = typeof obj.currency === 'string' ? obj.currency.toLowerCase() : null;
    }

    if (event.type.startsWith('customer.subscription.')) {
        const firstItem = obj.items?.data?.[0];
        data.subscription_id = getId(obj.id);
        data.customer_id = getId(obj.customer);
        data.subscription_status = typeof obj.status === 'string' ? obj.status : null;
        data.price_id = getId(firstItem?.price);
        data.product_id = getId(firstItem?.price?.product);
        data.quantity = typeof firstItem?.quantity === 'number' ? firstItem.quantity : null;
        data.current_period_start = unixToDate(obj.current_period_start);
        data.current_period_end = unixToDate(obj.current_period_end);
        data.cancel_at_period_end = Boolean(obj.cancel_at_period_end);
        data.cancel_at = unixToDate(obj.cancel_at);
        data.canceled_at = unixToDate(obj.canceled_at);
        data.ended_at = unixToDate(obj.ended_at);
        data.trial_start = unixToDate(obj.trial_start);
        data.trial_end = unixToDate(obj.trial_end);
        data.collection_method = typeof obj.collection_method === 'string' ? obj.collection_method : null;
        data.currency = typeof obj.currency === 'string' ? obj.currency.toLowerCase() : null;
    }

    if (event.type === 'invoice.paid' || event.type === 'invoice.payment_failed') {
        data.last_invoice_id = getId(obj.id);
        data.last_invoice_status = typeof obj.status === 'string' ? obj.status : null;
        data.last_payment_status = event.type === 'invoice.paid' ? 'paid' : 'failed';
        data.customer_id = getId(obj.customer);
        data.invoice_subscription_id = getId(obj.subscription) || getId(obj.parent?.subscription_details?.subscription);
        data.invoice_amount_due = typeof obj.amount_due === 'number' ? obj.amount_due : 0;
        data.invoice_amount_paid = typeof obj.amount_paid === 'number' ? obj.amount_paid : 0;
        data.invoice_currency = typeof obj.currency === 'string' ? obj.currency.toLowerCase() : null;
        data.invoice_created_at = unixToDate(obj.created);
        data.invoice_paid_at = unixToDate(obj.status_transitions?.paid_at);
        data.hosted_invoice_url = typeof obj.hosted_invoice_url === 'string' ? obj.hosted_invoice_url : null;
        data.invoice_pdf = typeof obj.invoice_pdf === 'string' ? obj.invoice_pdf : null;
    }

    if (event.type.startsWith('payout.')) {
        data.last_payout_id = getId(obj.id);
        data.last_payout_status = typeof obj.status === 'string' ? obj.status : null;
        data.last_payout_type = typeof obj.type === 'string' ? obj.type : null;
        data.last_payout_amount = typeof obj.amount === 'number' ? obj.amount : null;
        data.last_payout_currency = typeof obj.currency === 'string' ? obj.currency.toLowerCase() : null;
        data.last_payout_method = typeof obj.method === 'string' ? obj.method : null;
        data.last_payout_arrival_date = unixToDate(obj.arrival_date);
        data.last_payout_created_at = unixToDate(obj.created);
        data.last_payout_failure_code = typeof obj.failure_code === 'string' ? obj.failure_code : null;
        data.last_payout_failure_message = typeof obj.failure_message === 'string' ? obj.failure_message : null;
        data.last_payout_reconciliation_status = event.type === 'payout.reconciliation_completed' ? 'completed' : null;
        data.stripe_account_id = getId(event.account);
    }

    return data;
}

function getPlanKey(subscriptionObject) {
    const priceId = getId(subscriptionObject?.items?.data?.[0]?.price);
    if (priceId && process.env.STRIPE_PRICE_BASE && priceId === process.env.STRIPE_PRICE_BASE) return 'base';
    if (priceId && process.env.STRIPE_PRICE_STANDARD && priceId === process.env.STRIPE_PRICE_STANDARD) return 'standard';
    if (priceId && process.env.STRIPE_PRICE_PREMIUM && priceId === process.env.STRIPE_PRICE_PREMIUM) return 'premium';
    const metadataPlan = String(subscriptionObject?.metadata?.plan || '').toLowerCase().trim();
    if (ALLOWED_PLANS.has(metadataPlan)) return metadataPlan;
    return null;
}

function applyCheckoutEvent(payments, event) {
    const obj = event.data.object;
    const metadata = obj.metadata && typeof obj.metadata === 'object' ? obj.metadata : {};
    const paymentType = metadata.payment_type;

    if (paymentType === 'project_installment') {
        const number = Number(metadata.installment_number);
        if (![1, 2, 3].includes(number)) return payments;

        const rateKey = `rata_${number}`;
        const project = payments.progetto && typeof payments.progetto === 'object' ? payments.progetto : {};
        const rates = project.rate && typeof project.rate === 'object' ? project.rate : {};
        const currentRate = rates[rateKey] && typeof rates[rateKey] === 'object' ? rates[rateKey] : {};
        const sessionId = getId(obj.id);

        if (currentRate.stato === 'paid') {
            return payments;
        }

        const isPaidEvent = event.type === 'checkout.session.async_payment_succeeded'
            || (event.type === 'checkout.session.completed' && obj.payment_status === 'paid');
        const isFailedOrExpired = event.type === 'checkout.session.async_payment_failed'
            || event.type === 'checkout.session.expired';

        if (isPaidEvent) {
            const expectedAmount = Number(currentRate.importo_cent);
            const actualAmount = Number(obj.amount_total);
            const expectedCurrency = String(project.valuta || 'eur').toLowerCase().trim();
            const actualCurrency = String(obj.currency || '').toLowerCase().trim();
            const validExpectedAmount = Number.isInteger(expectedAmount) && expectedAmount > 0;
            const validActualAmount = Number.isInteger(actualAmount) && actualAmount >= 0;

            if (!validExpectedAmount || !validActualAmount || actualAmount !== expectedAmount || actualCurrency !== expectedCurrency) {
                rates[rateKey] = {
                    ...currentRate,
                    stato: 'manual_review',
                    importo_ricevuto_cent: validActualAmount ? actualAmount : null,
                    valuta_ricevuta: actualCurrency || null,
                    checkout_session_id: sessionId,
                    verifica_pagamento_richiesta: true
                };
            } else {
                rates[rateKey] = {
                    ...currentRate,
                    stato: 'paid',
                    paid_at: unixToDate(event.created),
                    checkout_session_id: sessionId,
                    payment_intent_id: getId(obj.payment_intent),
                    importo_pagato_cent: actualAmount
                };
            }
        } else if (
            isFailedOrExpired &&
            (!currentRate.checkout_session_id || currentRate.checkout_session_id === sessionId)
        ) {
            rates[rateKey] = {
                ...currentRate,
                stato: 'unlocked',
                checkout_session_id: null,
                checkout_created_at: null
            };
        }

        const paidCents = ['rata_1', 'rata_2', 'rata_3'].reduce((sum, key) => {
            const rate = rates[key];
            if (rate && rate.stato === 'paid') {
                const amt = Number(rate.importo_pagato_cent ?? rate.importo_cent ?? 0);
                return sum + (Number.isFinite(amt) && amt > 0 ? amt : 0);
            }
            return sum;
        }, 0);

        const totalCents = Number.isFinite(Number(project.totale_cent)) ? Math.max(0, Number(project.totale_cent)) : 0;
        payments.progetto = {
            ...project,
            rate: rates,
            totale_pagato_cent: paidCents,
            residuo_cent: Math.max(0, totalCents - paidCents),
            stato: totalCents > 0 && paidCents >= totalCents ? 'completato' : 'in_corso'
        };
    }

    if (paymentType === 'subscription' && event.type === 'checkout.session.completed') {
        const subscription = payments.abbonamento && typeof payments.abbonamento === 'object' ? payments.abbonamento : {};
        const currentStatus = String(subscription.stato || '').toLowerCase().trim();
        const metaPlan = String(metadata.plan || '').toLowerCase().trim();
        const safePlan = ALLOWED_PLANS.has(metaPlan)
            ? metaPlan
            : (ALLOWED_PLANS.has(subscription.piano_scelto) ? subscription.piano_scelto : null);

        payments.abbonamento = {
            ...subscription,
            stato: STRIPE_SUBSCRIPTION_STATUSES.has(currentStatus) ? currentStatus : 'in_attivazione',
            attivazione_abilitata: false,
            piano_scelto: safePlan,
            checkout_session_id: getId(obj.id),
            stripe_subscription_id: getId(obj.subscription) || getId(subscription.stripe_subscription_id),
            customer_id: getId(obj.customer) || getId(subscription.customer_id)
        };
    }

    if (
        paymentType === 'subscription' &&
        (event.type === 'checkout.session.async_payment_failed' || event.type === 'checkout.session.expired')
    ) {
        const subscription = payments.abbonamento && typeof payments.abbonamento === 'object' ? payments.abbonamento : {};
        const sessionId = getId(obj.id);
        if (subscription.checkout_session_id && subscription.checkout_session_id === sessionId && !getId(subscription.stripe_subscription_id)) {
            payments.abbonamento = {
                ...subscription,
                stato: subscription.attivazione_abilitata === true ? 'in_attesa_conferma_cliente' : 'in_attesa',
                checkout_session_id: null,
                checkout_created_at: null
            };
        }
    }

    return payments;
}

function applySubscriptionEvent(payments, event) {
    const obj = event.data.object;
    const subscription = payments.abbonamento && typeof payments.abbonamento === 'object' ? payments.abbonamento : {};
    const incomingSubId = getId(obj.id);
    const existingSubId = getId(subscription.stripe_subscription_id);

    if (existingSubId && incomingSubId && existingSubId !== incomingSubId) {
        return payments;
    }

    const firstItem = obj.items?.data?.[0];
    const priceId = getId(firstItem?.price);
    const plan = getPlanKey(obj);
    const rawStatus = String(obj.status || '').toLowerCase().trim();
    const stripeStatus = STRIPE_SUBSCRIPTION_STATUSES.has(rawStatus) ? rawStatus : null;
    const qty = Number(firstItem?.quantity);

    payments.abbonamento = {
        ...subscription,
        stato: stripeStatus || subscription.stato || 'in_attesa',
        attivazione_abilitata: stripeStatus && ['active', 'trialing'].includes(stripeStatus)
            ? false
            : Boolean(subscription.attivazione_abilitata),
        piano_scelto: plan || (ALLOWED_PLANS.has(subscription.piano_scelto) ? subscription.piano_scelto : null),
        stripe_subscription_id: incomingSubId || existingSubId,
        price_id: priceId,
        customer_id: getId(obj.customer) || getId(subscription.customer_id),
        quantita: Number.isInteger(qty) && qty > 0 ? qty : 1,
        periodo_corrente_inizio: unixToDate(obj.current_period_start),
        periodo_corrente_fine: unixToDate(obj.current_period_end),
        rinnovo_automatico: obj.cancel_at_period_end !== true,
        cancellazione_programmata: obj.cancel_at_period_end === true,
        cancellato_il: unixToDate(obj.canceled_at),
        terminato_il: unixToDate(obj.ended_at)
    };
    return payments;
}

function applyInvoiceEvent(payments, event) {
    const obj = event.data.object;
    const subscriptionId = getId(obj.subscription) || getId(obj.parent?.subscription_details?.subscription);
    if (!subscriptionId) return payments;

    const subscription = payments.abbonamento && typeof payments.abbonamento === 'object' ? payments.abbonamento : {};
    const existingSubId = getId(subscription.stripe_subscription_id);
    if (existingSubId && existingSubId !== subscriptionId) {
        return payments;
    }

    const amountDue = Number(obj.amount_due);
    const amountPaid = Number(obj.amount_paid);

    payments.abbonamento = {
        ...subscription,
        ultima_fattura: {
            id: getId(obj.id),
            stato: typeof obj.status === 'string' ? obj.status : null,
            stato_pagamento: event.type === 'invoice.paid' ? 'paid' : 'failed',
            importo_dovuto_cent: Number.isFinite(amountDue) ? amountDue : 0,
            importo_pagato_cent: Number.isFinite(amountPaid) ? amountPaid : 0,
            valuta: typeof obj.currency === 'string' ? obj.currency.toLowerCase() : 'eur',
            creata_il: unixToDate(obj.created),
            pagata_il: unixToDate(obj.status_transitions?.paid_at),
            hosted_url: typeof obj.hosted_invoice_url === 'string' ? obj.hosted_invoice_url : null,
            pdf_url: typeof obj.invoice_pdf === 'string' ? obj.invoice_pdf : null
        }
    };
    return payments;
}

function buildProfilePayments(profileData, event) {
    const original = profileData && typeof profileData.pagamenti === 'object' && profileData.pagamenti !== null
        ? profileData.pagamenti
        : {};
    const payments = { ...original };

    if (original.progetto && typeof original.progetto === 'object') {
        payments.progetto = {
            ...original.progetto,
            rate: original.progetto.rate && typeof original.progetto.rate === 'object'
                ? { ...original.progetto.rate }
                : {}
        };
    }
    if (original.abbonamento && typeof original.abbonamento === 'object') {
        payments.abbonamento = { ...original.abbonamento };
    }

    const eventType = event.type;
    let nextPayments = payments;

    if (eventType.startsWith('checkout.session.')) {
        nextPayments = applyCheckoutEvent(nextPayments, event);
    }
    if (eventType.startsWith('customer.subscription.')) {
        nextPayments = applySubscriptionEvent(nextPayments, event);
    }
    if (eventType === 'invoice.paid' || eventType === 'invoice.payment_failed') {
        nextPayments = applyInvoiceEvent(nextPayments, event);
    }

    return cleanObject(nextPayments) || {};
}

module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ success: false, error: 'Method not allowed' });
    }

    let event;
    try {
        const signature = req.headers?.['stripe-signature'];
        if (typeof signature !== 'string' || !signature) {
            return res.status(400).json({ success: false, error: 'Missing Stripe signature' });
        }
        const rawBody = await readRawRequestBody(req);
        event = stripe.webhooks.constructEvent(rawBody, signature, WEBHOOK_SECRET);
    } catch (error) {
        const status = error && typeof error.status === 'number' && error.status >= 400 && error.status < 500
            ? error.status
            : 400;
        const message = status === 413 ? 'Webhook body too large' : 'Invalid Stripe signature';
        return res.status(status).json({ success: false, error: message });
    }

    try {
        if (!event || typeof event.id !== 'string' || !isSafeDocId(event.id) || typeof event.type !== 'string') {
            return res.status(400).json({ success: false, error: 'Malformed webhook event' });
        }

        if (!ALLOWED_EVENT_TYPES.has(event.type)) {
            return res.status(200).json({ success: true, status: 'ignored', reason: 'unsupported_event_type' });
        }

        const obj = event.data?.object;
        if (!obj || typeof obj !== 'object') {
            return res.status(400).json({ success: false, error: 'Missing event payload object' });
        }

        const userid = await findUserId(event, obj);
        if (!userid) {
            return res.status(200).json({ success: true, status: 'ignored', reason: 'user_not_found' });
        }

        await saveStripeMappings(userid, obj, event);

        const userRef = db.collection('users').doc(userid);
        const profileRef = db.collection('utenti_dashboard').doc(userid);
        const eventRef = userRef.collection('stripeEvents').doc(event.id);
        const stripeData = extractStripeData(event);
        const sanitizedObj = cleanObject(obj) || {};

        const result = await db.runTransaction(async transaction => {
            const existingEvent = await transaction.get(eventRef);
            if (existingEvent.exists) return 'duplicate';

            const profileSnapshot = await transaction.get(profileRef);
            transaction.set(userRef, { userid, stripe: stripeData }, { merge: true });
            transaction.set(eventRef, {
                event_id: event.id,
                type: event.type,
                created: unixToDate(event.created),
                received_at: admin.firestore.FieldValue.serverTimestamp(),
                data: sanitizedObj
            });

            if (profileSnapshot.exists && (
                event.type.startsWith('checkout.session.') ||
                event.type.startsWith('customer.subscription.') ||
                event.type === 'invoice.paid' ||
                event.type === 'invoice.payment_failed'
            )) {
                const payments = buildProfilePayments(profileSnapshot.data() || {}, event);
                if (Object.keys(payments).length) {
                    transaction.set(profileRef, {
                        pagamenti: payments,
                        pagamenti_aggiornati_il: admin.firestore.FieldValue.serverTimestamp()
                    }, { merge: true });
                }
            }
            return 'processed';
        });

        return res.status(200).json({ success: true, status: result, userid, event: event.type });
    } catch (error) {
        if (error && typeof error.status === 'number' && error.status >= 400 && error.status < 500) {
            return res.status(error.status).json({ success: false, error: 'Invalid webhook payload' });
        }
        return res.status(500).json({ success: false, error: 'Webhook processing failed' });
    }
};

module.exports.config = { api: { bodyParser: false } };

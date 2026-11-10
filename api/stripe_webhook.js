'use strict';

const {
    admin,
    db,
    stripe
} = require('../lib/stripe');

const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
if (!WEBHOOK_SECRET) throw new Error('Missing STRIPE_WEBHOOK_SECRET');

function getId(value) {
    if (!value) return null;
    return typeof value === 'string' ? value : (value.id || null);
}

function unixToDate(value) {
    return value ? new Date(value * 1000) : null;
}

function cleanObject(obj) {
    return JSON.parse(JSON.stringify(obj));
}

async function readRawRequestBody(req) {
    if (Buffer.isBuffer(req.rawBody)) return req.rawBody;
    if (typeof req.rawBody === 'string') return Buffer.from(req.rawBody, 'utf8');

    const chunks = [];
    let totalBytes = 0;
    const maxBytes = 2 * 1024 * 1024;
    for await (const chunk of req) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += buffer.length;
        if (totalBytes > maxBytes) {
            const error = new Error('Webhook body too large');
            error.status = 413;
            throw error;
        }
        chunks.push(buffer);
    }
    if (!totalBytes) {
        const error = new Error('Raw webhook body is empty');
        error.status = 400;
        throw error;
    }
    return Buffer.concat(chunks, totalBytes);
}

async function resolveMigratedUserId(userId) {
    if (typeof userId !== 'string' || !userId) return null;
    const legacyProfile = await db.collection('utenti_dashboard').doc(userId).get();
    const migratedUid = legacyProfile.exists ? legacyProfile.data()?.migrated_to_uid : null;
    return typeof migratedUid === 'string' && migratedUid ? migratedUid : userId;
}

async function findUserId(event, obj) {
    const metadata = obj?.metadata || obj?.parent?.subscription_details?.metadata || {};
    const metadataUserId = metadata.userid || metadata.userId || obj?.client_reference_id;
    if (metadataUserId) return resolveMigratedUserId(metadataUserId);

    const accountId = event.account || null;
    if (accountId) {
        const accountDoc = await db.collection('stripeAccounts').doc(accountId).get();
        if (accountDoc.exists && accountDoc.data()?.userid) {
            return resolveMigratedUserId(accountDoc.data().userid);
        }
    }

    const customerId = getId(obj.customer);
    if (customerId) {
        const customerDoc = await db.collection('stripeCustomers').doc(customerId).get();
        if (customerDoc.exists && customerDoc.data()?.userid) {
            return resolveMigratedUserId(customerDoc.data().userid);
        }
    }

    let subscriptionId = getId(obj.subscription)
        || getId(obj.parent?.subscription_details?.subscription);
    if (!subscriptionId && obj.object === 'subscription') subscriptionId = obj.id;

    if (subscriptionId) {
        const subscriptionDoc = await db.collection('stripeSubscriptions').doc(subscriptionId).get();
        if (subscriptionDoc.exists && subscriptionDoc.data()?.userid) {
            return resolveMigratedUserId(subscriptionDoc.data().userid);
        }
    }

    return null;
}

async function saveStripeMappings(userid, obj, event) {
    const batch = db.batch();
    const customerId = getId(obj.customer);
    const subscriptionId = getId(obj.subscription)
        || (obj.object === 'subscription' ? obj.id : null)
        || getId(obj.parent?.subscription_details?.subscription);
    const accountId = event.account || (obj.object === 'account' ? obj.id : null);

    if (customerId) {
        batch.set(db.collection('stripeCustomers').doc(customerId), { userid }, { merge: true });
    }
    if (subscriptionId) {
        batch.set(db.collection('stripeSubscriptions').doc(subscriptionId), { userid }, { merge: true });
    }
    if (accountId) {
        batch.set(db.collection('stripeAccounts').doc(accountId), { userid }, { merge: true });
    }
    await batch.commit();
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
        data.checkout_session_id = obj.id;
        data.checkout_status = obj.status;
        data.payment_status = obj.payment_status || null;
        data.customer_id = getId(obj.customer);
        data.subscription_id = getId(obj.subscription);
        data.checkout_mode = obj.mode;
        data.checkout_amount_total = obj.amount_total ?? null;
        data.checkout_currency = obj.currency || null;
    }

    if (event.type.startsWith('customer.subscription.')) {
        data.subscription_id = obj.id;
        data.customer_id = getId(obj.customer);
        data.subscription_status = obj.status;
        data.price_id = obj.items?.data?.[0]?.price?.id || null;
        data.product_id = getId(obj.items?.data?.[0]?.price?.product);
        data.quantity = obj.items?.data?.[0]?.quantity ?? null;
        data.current_period_start = unixToDate(obj.current_period_start);
        data.current_period_end = unixToDate(obj.current_period_end);
        data.cancel_at_period_end = obj.cancel_at_period_end;
        data.cancel_at = unixToDate(obj.cancel_at);
        data.canceled_at = unixToDate(obj.canceled_at);
        data.ended_at = unixToDate(obj.ended_at);
        data.trial_start = unixToDate(obj.trial_start);
        data.trial_end = unixToDate(obj.trial_end);
        data.collection_method = obj.collection_method;
        data.currency = obj.currency;
    }

    if (event.type === 'invoice.paid' || event.type === 'invoice.payment_failed') {
        data.last_invoice_id = obj.id;
        data.last_invoice_status = obj.status;
        data.last_payment_status = event.type === 'invoice.paid' ? 'paid' : 'failed';
        data.customer_id = getId(obj.customer);
        data.invoice_subscription_id = getId(obj.subscription)
            || getId(obj.parent?.subscription_details?.subscription);
        data.invoice_amount_due = obj.amount_due;
        data.invoice_amount_paid = obj.amount_paid;
        data.invoice_currency = obj.currency;
        data.invoice_created_at = unixToDate(obj.created);
        data.invoice_paid_at = unixToDate(obj.status_transitions?.paid_at);
        data.hosted_invoice_url = obj.hosted_invoice_url || null;
        data.invoice_pdf = obj.invoice_pdf || null;
    }

    if (event.type.startsWith('payout.')) {
        data.last_payout_id = obj.id;
        data.last_payout_status = obj.status;
        data.last_payout_type = obj.type;
        data.last_payout_amount = obj.amount;
        data.last_payout_currency = obj.currency;
        data.last_payout_method = obj.method;
        data.last_payout_arrival_date = unixToDate(obj.arrival_date);
        data.last_payout_created_at = unixToDate(obj.created);
        data.last_payout_failure_code = obj.failure_code || null;
        data.last_payout_failure_message = obj.failure_message || null;
        data.last_payout_reconciliation_status = event.type === 'payout.reconciliation_completed' ? 'completed' : null;
        data.stripe_account_id = event.account || null;
    }

    return data;
}

function getPlanKey(subscriptionObject) {
    const priceId = subscriptionObject?.items?.data?.[0]?.price?.id;
    if (priceId && priceId === process.env.STRIPE_PRICE_BASE) return 'base';
    if (priceId && priceId === process.env.STRIPE_PRICE_STANDARD) return 'standard';
    if (priceId && priceId === process.env.STRIPE_PRICE_PREMIUM) return 'premium';
    const metadataPlan = String(subscriptionObject?.metadata?.plan || '').toLowerCase();
    if (['base', 'standard', 'premium'].includes(metadataPlan)) return metadataPlan;
    return null;
}

function applyCheckoutEvent(payments, event) {
    const obj = event.data.object;
    const metadata = obj.metadata || {};
    const paymentType = metadata.payment_type;

    if (paymentType === 'project_installment') {
        const number = Number(metadata.installment_number);
        if (![1, 2, 3].includes(number)) return payments;
        const rateKey = `rata_${number}`;
        const project = payments.progetto || {};
        const rates = project.rate || {};
        const currentRate = rates[rateKey] || {};
        const isPaidEvent = event.type === 'checkout.session.async_payment_succeeded'
            || (event.type === 'checkout.session.completed' && obj.payment_status === 'paid');
        const isFailedOrExpired = event.type === 'checkout.session.async_payment_failed'
            || event.type === 'checkout.session.expired';

        if (isPaidEvent) {
            const expectedAmount = Number(currentRate.importo_cent || 0);
            const actualAmount = Number(obj.amount_total || 0);
            const expectedCurrency = String(project.valuta || 'eur').toLowerCase();
            const actualCurrency = String(obj.currency || '').toLowerCase();

            if (expectedAmount <= 0 || actualAmount !== expectedAmount || actualCurrency !== expectedCurrency) {
                rates[rateKey] = {
                    ...currentRate,
                    stato: 'manual_review',
                    importo_ricevuto_cent: actualAmount,
                    valuta_ricevuta: actualCurrency,
                    verifica_pagamento_richiesta: true
                };
            } else {
                rates[rateKey] = {
                    ...currentRate,
                    stato: 'paid',
                    paid_at: unixToDate(event.created),
                    checkout_session_id: obj.id,
                    payment_intent_id: getId(obj.payment_intent),
                    importo_pagato_cent: actualAmount
                };
            }
        } else if (
            isFailedOrExpired &&
            currentRate.stato !== 'paid' &&
            (!currentRate.checkout_session_id || currentRate.checkout_session_id === obj.id)
        ) {
            rates[rateKey] = {
                ...currentRate,
                stato: 'unlocked',
                checkout_session_id: null,
                checkout_created_at: null
            };
        }

        const paidCents = ['rata_1', 'rata_2', 'rata_3'].reduce((sum, key) => {
            const rate = rates[key] || {};
            return sum + (rate.stato === 'paid' ? Number(rate.importo_cent || 0) : 0);
        }, 0);
        payments.progetto = {
            ...project,
            rate: rates,
            totale_pagato_cent: paidCents,
            residuo_cent: Math.max(0, Number(project.totale_cent || 0) - paidCents),
            stato: paidCents >= Number(project.totale_cent || 0) ? 'completato' : 'in_corso'
        };
    }

    if (paymentType === 'subscription' && event.type === 'checkout.session.completed') {
        const subscription = payments.abbonamento || {};
        const currentStatus = String(subscription.stato || '').toLowerCase();
        const stripeStatuses = [
            'incomplete', 'incomplete_expired', 'trialing', 'active',
            'past_due', 'canceled', 'unpaid', 'paused'
        ];
        payments.abbonamento = {
            ...subscription,
            stato: stripeStatuses.includes(currentStatus) ? currentStatus : 'in_attivazione',
            attivazione_abilitata: false,
            piano_scelto: String(metadata.plan || subscription.piano_scelto || '').toLowerCase(),
            checkout_session_id: obj.id,
            stripe_subscription_id: getId(obj.subscription) || subscription.stripe_subscription_id || null,
            customer_id: getId(obj.customer) || subscription.customer_id || null
        };
    }
    if (
        paymentType === 'subscription' &&
        (event.type === 'checkout.session.async_payment_failed' || event.type === 'checkout.session.expired')
    ) {
        const subscription = payments.abbonamento || {};
        if (subscription.checkout_session_id === obj.id && !subscription.stripe_subscription_id) {
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
    const subscription = payments.abbonamento || {};
    const priceId = obj.items?.data?.[0]?.price?.id || null;
    const plan = getPlanKey(obj);
    const stripeStatus = String(obj.status || '').toLowerCase();
    payments.abbonamento = {
        ...subscription,
        stato: stripeStatus || subscription.stato || 'in_attesa',
        attivazione_abilitata: ['active', 'trialing'].includes(stripeStatus) ? false : subscription.attivazione_abilitata,
        piano_scelto: plan || subscription.piano_scelto || null,
        stripe_subscription_id: obj.id,
        price_id: priceId,
        customer_id: getId(obj.customer),
        quantita: obj.items?.data?.[0]?.quantity ?? 1,
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
    const subscriptionId = getId(obj.subscription)
        || getId(obj.parent?.subscription_details?.subscription);
    if (!subscriptionId) return payments;

    const subscription = payments.abbonamento || {};
    payments.abbonamento = {
        ...subscription,
        ultima_fattura: {
            id: obj.id,
            stato: obj.status || null,
            stato_pagamento: event.type === 'invoice.paid' ? 'paid' : 'failed',
            importo_dovuto_cent: Number(obj.amount_due || 0),
            importo_pagato_cent: Number(obj.amount_paid || 0),
            valuta: obj.currency || 'eur',
            creata_il: unixToDate(obj.created),
            pagata_il: unixToDate(obj.status_transitions?.paid_at),
            hosted_url: obj.hosted_invoice_url || null,
            pdf_url: obj.invoice_pdf || null
        }
    };
    return payments;
}

function buildProfilePayments(profileData, event) {
    const original = profileData.pagamenti || {};
    let payments = { ...original };
    if (original.progetto && typeof original.progetto === 'object') {
        payments.progetto = {
            ...original.progetto,
            rate: { ...(original.progetto.rate || {}) }
        };
    }
    if (original.abbonamento && typeof original.abbonamento === 'object') {
        payments.abbonamento = { ...original.abbonamento };
    }
    const eventType = event.type;

    if (eventType.startsWith('checkout.session.')) {
        payments = applyCheckoutEvent(payments, event);
    }
    if (eventType.startsWith('customer.subscription.')) {
        payments = applySubscriptionEvent(payments, event);
    }
    if (eventType === 'invoice.paid' || eventType === 'invoice.payment_failed') {
        payments = applyInvoiceEvent(payments, event);
    }

    return payments;
}

module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, error: 'Method not allowed' });
    }

    let event;
    try {
        const signature = req.headers['stripe-signature'];
        if (!signature) {
            return res.status(400).json({ success: false, error: 'Missing Stripe signature' });
        }
        const rawBody = await readRawRequestBody(req);
        event = stripe.webhooks.constructEvent(rawBody, signature, WEBHOOK_SECRET);
    } catch (error) {
        console.error('Stripe signature error:', error.message);
        return res.status(400).json({ success: false, error: 'Invalid Stripe signature' });
    }

    try {
        const obj = event.data.object;
        console.log('Stripe event received:', event.type, event.id);

        const userid = await findUserId(event, obj);
        if (!userid) {
            console.error('User not found for Stripe event:', event.id, event.type);
            return res.status(200).json({ success: true, status: 'ignored', reason: 'user_not_found' });
        }

        await saveStripeMappings(userid, obj, event);

        const userRef = db.collection('users').doc(userid);
        const profileRef = db.collection('utenti_dashboard').doc(userid);
        const eventRef = userRef.collection('stripeEvents').doc(event.id);
        const stripeData = extractStripeData(event);

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
                data: cleanObject(obj)
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

        console.log(`Event ${event.id}: ${result} for user ${userid}`);
        return res.status(200).json({ success: true, status: result, userid, event: event.type });
    } catch (error) {
        console.error('Stripe webhook processing error:', error);
        return res.status(500).json({ success: false, error: 'Webhook processing failed' });
    }
};

module.exports.config = { api: { bodyParser: false } };

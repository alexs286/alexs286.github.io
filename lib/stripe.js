'use strict';

const admin = require('firebase-admin');
const Stripe = require('stripe');

const ALLOWED_ORIGIN = 'https://www.creatorweb.cc';
const SITE_URL = 'https://www.creatorweb.cc';

if (!admin.apps.length) {
    const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;
    if (!rawServiceAccount) throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_WORK');

    let serviceAccount;
    try {
        serviceAccount = typeof rawServiceAccount === 'string'
            ? JSON.parse(rawServiceAccount)
            : rawServiceAccount;
    } catch (_error) {
        throw new Error('FIREBASE_SERVICE_ACCOUNT_WORK non contiene un JSON valido');
    }

    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}

if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error('Missing STRIPE_SECRET_KEY');
}

const db = admin.firestore();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

function setCors(req, res) {
    const origin = req.headers.origin;
    if (!origin || origin === ALLOWED_ORIGIN) {
        res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    }
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'no-store, max-age=0');
}

function rejectOrigin(req) {
    return Boolean(req.headers.origin && req.headers.origin !== ALLOWED_ORIGIN);
}

function httpError(message, status = 400, code) {
    const error = new Error(message);
    error.status = status;
    if (code) error.code = code;
    return error;
}

async function requireCustomer(req) {
    const match = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
    if (!match) throw httpError('Autenticazione richiesta. Accedi nuovamente.', 401);

    let decoded;
    try {
        decoded = await admin.auth().verifyIdToken(match[1], true);
    } catch (_error) {
        throw httpError('Sessione non valida o scaduta.', 401);
    }

    const profileRef = db.collection('utenti_dashboard').doc(decoded.uid);
    const snapshot = await profileRef.get();
    if (!snapshot.exists) throw httpError('Profilo cliente non trovato.', 404);

    const profile = snapshot.data() || {};
    if (profile.account?.must_change_password === true) {
        throw httpError(
            'Prima di utilizzare i pagamenti devi modificare la password temporanea.',
            403,
            'PASSWORD_CHANGE_REQUIRED'
        );
    }

    return { uid: decoded.uid, profile, profileRef, decoded };
}

function planPriceConfig(plan) {
    const normalized = String(plan || '').trim().toLowerCase();
    const config = {
        base: {
            env: 'STRIPE_PRICE_BASE',
            label: 'Base',
            expectedAmount: 1000
        },
        standard: {
            env: 'STRIPE_PRICE_STANDARD',
            label: 'Standard',
            expectedAmount: 2000
        },
        premium: {
            env: 'STRIPE_PRICE_PREMIUM',
            label: 'Premium',
            expectedAmount: 5000
        }
    }[normalized];

    if (!config) throw httpError('Il piano mensile associato al profilo non è valido.', 409);
    const priceId = process.env[config.env];
    if (!priceId || !/^price_[A-Za-z0-9]+$/.test(priceId)) {
        throw httpError(`Configurazione Stripe mancante: ${config.env}.`, 503);
    }
    return { ...config, key: normalized, priceId };
}

async function getOrCreateStripeCustomer(uid, profile) {
    const mappingQuery = await db.collection('stripeCustomers')
        .where('userid', '==', uid)
        .limit(5)
        .get();

    let customerId = mappingQuery.docs[0]?.id || null;
    if (!customerId) {
        const privateSnapshot = await db.collection('users').doc(uid).get();
        customerId = privateSnapshot.exists
            ? (privateSnapshot.data()?.stripe?.customer_id || null)
            : null;
    }

    if (customerId) {
        try {
            const existing = await stripe.customers.retrieve(customerId);
            if (!existing.deleted) {
                await db.collection('stripeCustomers').doc(customerId).set({
                    userid: uid,
                    source: 'creatorweb_api'
                }, { merge: true });
                return existing;
            }
        } catch (error) {
            if (error.code !== 'resource_missing') throw error;
        }
    }

    const email = String(profile.email || '').trim().toLowerCase();
    if (!email) throw httpError('Il profilo non contiene un indirizzo email valido.', 409);

    const customer = await stripe.customers.create({
        email,
        name: [profile.nome, profile.cognome].filter(Boolean).join(' ').trim() || undefined,
        metadata: { userid: uid, creatorweb_uid: uid }
    }, {
        idempotencyKey: `creatorweb-customer-${uid}-${customerId || 'initial'}`
    });

    const batch = db.batch();
    batch.set(db.collection('stripeCustomers').doc(customer.id), {
        userid: uid,
        email,
        created_at: admin.firestore.FieldValue.serverTimestamp(),
        source: 'creatorweb_api'
    }, { merge: true });
    batch.set(db.collection('users').doc(uid), {
        userid: uid,
        stripe: {
            customer_id: customer.id,
            customer_email: email
        }
    }, { merge: true });
    await batch.commit();

    return customer;
}

async function retrieveUsableSubscriptionPrice(planConfig) {
    let price;
    try {
        price = await stripe.prices.retrieve(planConfig.priceId);
    } catch (_error) {
        throw httpError(`Il Price ID configurato per il piano ${planConfig.label} non esiste in questo account Stripe.`, 503);
    }

    if (
        !price.active ||
        price.currency !== 'eur' ||
        price.unit_amount !== planConfig.expectedAmount ||
        price.recurring?.interval !== 'month' ||
        price.recurring?.interval_count !== 1
    ) {
        throw httpError(
            `Il prezzo Stripe del piano ${planConfig.label} deve essere attivo, in EUR, mensile e di €${(planConfig.expectedAmount / 100).toFixed(2)}.`,
            503
        );
    }
    return price;
}

module.exports = {
    admin,
    db,
    stripe,
    ALLOWED_ORIGIN,
    SITE_URL,
    setCors,
    rejectOrigin,
    httpError,
    requireCustomer,
    planPriceConfig,
    getOrCreateStripeCustomer,
    retrieveUsableSubscriptionPrice
};

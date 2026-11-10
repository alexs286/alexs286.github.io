'use strict';

const {
    stripe,
    SITE_URL,
    setCors,
    rejectOrigin,
    requireCustomer,
    getOrCreateStripeCustomer
} = require('../lib/stripe');

module.exports = async function handler(req, res) {
    setCors(req, res);
    if (req.method === 'OPTIONS') return res.status(204).end();
    if (rejectOrigin(req)) return res.status(403).json({ error: 'Origin non autorizzata.' });
    if (req.method !== 'POST') return res.status(405).json({ error: 'Metodo non consentito.' });

    try {
        const { uid, profile } = await requireCustomer(req);
        const customer = await getOrCreateStripeCustomer(uid, profile);
        const session = await stripe.billingPortal.sessions.create({
            customer: customer.id,
            return_url: `${SITE_URL}/dashboard.html`
        });

        return res.status(200).json({ success: true, url: session.url });
    } catch (error) {
        console.error('Stripe Portal API error:', error);
        return res.status(error.status || 500).json({
            error: error.status
                ? error.message
                : 'Non è stato possibile aprire il portale Stripe. Verifica che il portale clienti sia abilitato nel tuo account Stripe.'
        });
    }
};

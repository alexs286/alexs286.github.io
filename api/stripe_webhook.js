
const Stripe = require("stripe");
const admin = require("firebase-admin");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const ALLOWED_ORIGIN = "https://www.creatorweb.cc";
if (!admin.apps.length) {
    const serviceAccount = JSON.parse(
        process.env.FIREBASE_SERVICE_ACCOUNT_WORK
    );

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();

function setCors(req, res) {
    res.setHeader(
        "Access-Control-Allow-Origin",
        ALLOWED_ORIGIN
    );

    res.setHeader(
        "Access-Control-Allow-Methods",
        "POST, OPTIONS"
    );

    res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Stripe-Signature, Authorization"
    );
}

function getId(value) {
    if (!value) return null;

    return typeof value === "string"
        ? value
        : value.id || null;
}

function unixToDate(value) {
    return value
        ? new Date(value * 1000)
        : null;
}

function cleanObject(obj) {
    return JSON.parse(JSON.stringify(obj));
}

async function findUserId(event, obj) {

    const metadataUserId =
        obj?.metadata?.userid ||
        obj?.metadata?.userId;

    if (metadataUserId) {
        return metadataUserId;
    }

    const accountId = event.account || null;

    if (accountId) {
        const doc = await db
            .collection("stripeAccounts")
            .doc(accountId)
            .get();

        if (doc.exists) {
            return doc.data().userid;
        }
    }

    const customerId = getId(obj.customer);

    if (customerId) {
        const doc = await db
            .collection("stripeCustomers")
            .doc(customerId)
            .get();

        if (doc.exists) {
            return doc.data().userid;
        }
    }

    let subscriptionId =
        getId(obj.subscription) ||
        getId(obj.parent?.subscription_details?.subscription);

    if (
        !subscriptionId &&
        obj.object === "subscription"
    ) {
        subscriptionId = obj.id;
    }

    if (subscriptionId) {
        const doc = await db
            .collection("stripeSubscriptions")
            .doc(subscriptionId)
            .get();

        if (doc.exists) {
            return doc.data().userid;
        }
    }

    return null;
}

async function saveStripeMappings(userid, obj, event) {

    const batch = db.batch();

    const customerId = getId(obj.customer);

    const subscriptionId =
        getId(obj.subscription) ||
        (obj.object === "subscription" ? obj.id : null);

    const accountId =
        event.account ||
        (obj.object === "account" ? obj.id : null);

    if (customerId) {
        batch.set(
            db.collection("stripeCustomers").doc(customerId),
            { userid },
            { merge: true }
        );
    }

    if (subscriptionId) {
        batch.set(
            db.collection("stripeSubscriptions").doc(subscriptionId),
            { userid },
            { merge: true }
        );
    }

    if (accountId) {
        batch.set(
            db.collection("stripeAccounts").doc(accountId),
            { userid },
            { merge: true }
        );
    }

    await batch.commit();
}

function extractStripeData(event) {

    const obj = event.data.object;

    const data = {
        last_event_id: event.id,
        last_event_type: event.type,
        last_event_created: unixToDate(event.created),
        last_event_received_at:
            admin.firestore.FieldValue.serverTimestamp()
    };
    if (event.type === "checkout.session.completed") {

        data.checkout_session_id = obj.id;
        data.checkout_status = obj.status;
        data.payment_status = obj.payment_status;

        data.customer_id = getId(obj.customer);
        data.subscription_id = getId(obj.subscription);

        data.checkout_mode = obj.mode;
    }
    if (event.type.startsWith("customer.subscription.")) {

        data.subscription_id = obj.id;
        data.customer_id = getId(obj.customer);

        data.subscription_status = obj.status;

        data.price_id =
            obj.items?.data?.[0]?.price?.id || null;

        data.product_id =
            getId(obj.items?.data?.[0]?.price?.product);

        data.quantity =
            obj.items?.data?.[0]?.quantity ?? null;

        data.current_period_start =
            unixToDate(obj.current_period_start);

        data.current_period_end =
            unixToDate(obj.current_period_end);

        data.cancel_at_period_end =
            obj.cancel_at_period_end;

        data.cancel_at = unixToDate(obj.cancel_at);
        data.canceled_at = unixToDate(obj.canceled_at);
        data.ended_at = unixToDate(obj.ended_at);

        data.trial_start = unixToDate(obj.trial_start);
        data.trial_end = unixToDate(obj.trial_end);

        data.collection_method = obj.collection_method;
        data.currency = obj.currency;
    }
    if (
        event.type === "invoice.paid" ||
        event.type === "invoice.payment_failed"
    ) {

        data.last_invoice_id = obj.id;
        data.last_invoice_status = obj.status;

        data.last_payment_status =
            event.type === "invoice.paid"
                ? "paid"
                : "failed";

        data.customer_id = getId(obj.customer);

        data.invoice_subscription_id =
            getId(obj.subscription) ||
            getId(obj.parent?.subscription_details?.subscription);

        data.invoice_amount_due = obj.amount_due;
        data.invoice_amount_paid = obj.amount_paid;
        data.invoice_currency = obj.currency;

        data.invoice_created_at =
            unixToDate(obj.created);

        data.invoice_paid_at =
            unixToDate(obj.status_transitions?.paid_at);

        data.hosted_invoice_url =
            obj.hosted_invoice_url || null;

        data.invoice_pdf =
            obj.invoice_pdf || null;
    }
    if (event.type.startsWith("payout.")) {

        data.last_payout_id = obj.id;
        data.last_payout_status = obj.status;

        data.last_payout_type = obj.type;
        data.last_payout_amount = obj.amount;
        data.last_payout_currency = obj.currency;

        data.last_payout_method = obj.method;

        data.last_payout_arrival_date =
            unixToDate(obj.arrival_date);

        data.last_payout_created_at =
            unixToDate(obj.created);

        data.last_payout_failure_code =
            obj.failure_code || null;

        data.last_payout_failure_message =
            obj.failure_message || null;

        data.last_payout_reconciliation_status =
            event.type === "payout.reconciliation_completed"
                ? "completed"
                : null;

        data.stripe_account_id =
            event.account || null;
    }

    return data;
}

module.exports = async (req, res) => {

    setCors(req, res);

    if (req.method === "OPTIONS") {
        return res.status(204).end();
    }

    if (req.method !== "POST") {
        return res.status(405).json({
            success: false,
            error: "Method not allowed"
        });
    }

    let event;

    try {

        const signature =
            req.headers["stripe-signature"];

        if (!signature) {
            return res.status(400).json({
                success: false,
                error: "Missing Stripe signature"
            });
        }

        const rawBody = req.body;

        if (
            !Buffer.isBuffer(rawBody) &&
            typeof rawBody !== "string"
        ) {
            return res.status(400).json({
                success: false,
                error: "Raw request body is required"
            });
        }

        event = stripe.webhooks.constructEvent(
            rawBody,
            signature,
            WEBHOOK_SECRET
        );

    } catch (error) {

        console.error(
            "Stripe signature error:",
            error.message
        );

        return res.status(400).json({
            success: false,
            error: "Invalid Stripe signature"
        });
    }

    try {

        console.log(
            "Stripe event received:",
            event.type,
            event.id
        );

        const obj = event.data.object;

        const userid = await findUserId(event, obj);

        if (!userid) {

            console.error(
                "User not found:",
                event.id,
                event.type
            );

            return res.status(500).json({
                success: false,
                error: "Unable to identify user"
            });
        }

        const userRef = db
            .collection("users")
            .doc(userid);

        const eventRef = userRef
            .collection("stripeEvents")
            .doc(event.id);

        const stripeData = extractStripeData(event);

        await saveStripeMappings(
            userid,
            obj,
            event
        );

        const result = await db.runTransaction(
            async (transaction) => {

                const existingEvent =
                    await transaction.get(eventRef);

                if (existingEvent.exists) {
                    return "duplicate";
                }

                transaction.set(
                    userRef,
                    {
                        userid: userid,
                        stripe: stripeData
                    },
                    { merge: true }
                );

                transaction.set(
                    eventRef,
                    {
                        event_id: event.id,
                        type: event.type,
                        created: unixToDate(event.created),
                        received_at:
                            admin.firestore.FieldValue.serverTimestamp(),
                        data: cleanObject(obj)
                    }
                );

                return "processed";
            }
        );

        console.log(
            `Event ${event.id}: ${result} for user ${userid}`
        );

        return res.status(200).json({
            success: true,
            status: result,
            userid: userid,
            event: event.type
        });

    } catch (error) {

        console.error(
            "Stripe webhook processing error:",
            error
        );

        return res.status(500).json({
            success: false,
            error: "Webhook processing failed"
        });
    }
};

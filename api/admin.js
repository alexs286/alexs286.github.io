const admin = require('firebase-admin');
const crypto = require('crypto');

if (!admin.apps.length) {
    const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;

    if (!rawServiceAccount) {
        throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_WORK');
    }

    let serviceAccount;
    try {
        serviceAccount = typeof rawServiceAccount === 'string'
            ? JSON.parse(rawServiceAccount)
            : rawServiceAccount;
    } catch (error) {
        throw new Error('FIREBASE_SERVICE_ACCOUNT_WORK non contiene un JSON valido');
    }

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();
const rateLimits = new Map();

const ALLOWED_ORIGIN = 'https://www.creatorweb.cc';
const ALLOWED_COLLECTIONS = new Set([
    'richieste_preventivo',
    'utenti_dashboard',
    'richieste_supporto',
    'stato del servizio'
]);

const USER_FIELDS = new Set([
    'email',
    'nome',
    'nome_utente',
    'cognome',
    'ruolo',
    'stato_sito',
    'stato_progetto',
    'telefono',
    'url_sito',
    'sito_web',
    'sito',
    'tipo_servizio',
    'budget',
    'budget_ref',
    'scadenza_dominio'
]);

const STATUS_VALUES = new Set([
    'pieno',
    'problemi tecnici',
    'errori di terzi',
    'servizio in pausa per festività',
    'manutenzione'
]);

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

function sendJson(res, status, body) {
    return res.status(status).json(body);
}

function checkRateLimit(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = (typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : '')
        || req.socket?.remoteAddress
        || 'unknown';

    const now = Date.now();
    const current = rateLimits.get(ip) || { count: 0, startedAt: now };

    if (now - current.startedAt >= 60000) {
        current.count = 0;
        current.startedAt = now;
    }

    current.count++;
    rateLimits.set(ip, current);

    if (rateLimits.size > 5000) {
        for (const [key, value] of rateLimits) {
            if (now - value.startedAt >= 60000) rateLimits.delete(key);
        }
    }

    return current.count > 100;
}

function cleanString(value, maxLength = 5000) {
    if (typeof value !== 'string') return '';
    return value.trim().slice(0, maxLength);
}

function validDocumentId(value) {
    return typeof value === 'string'
        && value.trim().length > 0
        && value.trim().length <= 150
        && !value.includes('/')
        && value.trim() === value;
}

function isValidDateOnly(value) {
    if (value === '') return true;
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;

    const [year, month, day] = value.split('-').map(Number);
    const date = new Date(Date.UTC(year, month - 1, day));
    return date.getUTCFullYear() === year
        && date.getUTCMonth() === month - 1
        && date.getUTCDate() === day;
}

function serializeData(value) {
    if (value === null || value === undefined) return value;
    if (typeof value.toDate === 'function') return value.toDate().toISOString();
    if (value instanceof Date) return value.toISOString();
    if (Array.isArray(value)) return value.map(serializeData);
    if (typeof value === 'object') {
        const result = {};
        for (const [key, child] of Object.entries(value)) {
            result[key] = serializeData(child);
        }
        return result;
    }
    return value;
}

function redactSensitiveFields(value) {
    if (Array.isArray(value)) return value.map(redactSensitiveFields);
    if (!value || typeof value !== 'object') return value;
    const result = {};
    for (const [key, child] of Object.entries(value)) {
        if (['password', 'passwordHash', 'codici_sicurezza_hash'].includes(key)) continue;
        result[key] = redactSensitiveFields(child);
    }
    return result;
}

async function verifyAdmin(req) {
    const header = req.headers.authorization || '';
    const match = header.match(/^Bearer\s+(.+)$/i);

    if (!match) {
        const error = new Error('Autenticazione richiesta. Effettua nuovamente l’accesso.');
        error.status = 401;
        throw error;
    }

    const allowedUids = (process.env.ADMIN_UIDS || '')
        .split(',')
        .map(uid => uid.trim())
        .filter(Boolean);

    if (allowedUids.length === 0) {
        const error = new Error('Configurazione amministratore mancante sul server.');
        error.status = 503;
        throw error;
    }

    let decoded;
    try {
        decoded = await admin.auth().verifyIdToken(match[1], true);
    } catch (_error) {
        const error = new Error('Sessione non valida o scaduta.');
        error.status = 401;
        throw error;
    }

    if (!allowedUids.includes(decoded.uid)) {
        const error = new Error('Non hai i permessi per accedere al pannello amministrativo.');
        error.status = 403;
        throw error;
    }

    return decoded;
}

function pickUserFields(source, creating = false) {
    const result = {};
    if (!source || typeof source !== 'object' || Array.isArray(source)) return result;

    for (const [key, value] of Object.entries(source)) {
        if (!USER_FIELDS.has(key)) continue;
        if (typeof value === 'string') {
            result[key] = cleanString(value, 2000);
        } else if (value === null && !creating) {
            result[key] = null;
        }
    }

    if (typeof result.email === 'string') {
        result.email = result.email.toLowerCase();
    }

    if (typeof result.nome_utente === 'string') {
        result.nome_utente = result.nome_utente.toLowerCase();
    }


    if (Object.prototype.hasOwnProperty.call(result, 'scadenza_dominio')
        && !isValidDateOnly(result.scadenza_dominio)) {
        throw Object.assign(new Error('La scadenza del dominio deve essere una data valida (AAAA-MM-GG).'), { status: 400 });
    }

    return result;
}

module.exports = async function handler(req, res) {
    setCors(req, res);

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    if (req.headers.origin && req.headers.origin !== ALLOWED_ORIGIN) {
        return sendJson(res, 403, { error: 'Origin non autorizzata' });
    }

    if (req.method !== 'POST') {
        return sendJson(res, 405, { error: 'Metodo non consentito' });
    }

    if (checkRateLimit(req)) {
        return sendJson(res, 429, { error: 'Troppe richieste. Riprova tra un minuto.' });
    }

    try {
        await verifyAdmin(req);

        const body = req.body && typeof req.body === 'object' ? req.body : {};
        const action = cleanString(body.action, 80);

        if (action === 'get_collection') {
            const collectionName = cleanString(body.collection, 100);

            if (!ALLOWED_COLLECTIONS.has(collectionName)) {
                return sendJson(res, 403, { error: 'Collezione non autorizzata' });
            }

            const snapshot = await db.collection(collectionName).get();
            const docs = snapshot.docs.map(doc => ({
                id: doc.id,
                data: redactSensitiveFields(serializeData(doc.data()))
            }));

            docs.sort((a, b) => {
                const dateA = a.data.data || a.data.createdAt || a.data.ultimo_aggiornamento || '';
                const dateB = b.data.data || b.data.createdAt || b.data.ultimo_aggiornamento || '';
                return String(dateB).localeCompare(String(dateA));
            });

            return sendJson(res, 200, { data: docs });
        }

        if (action === 'get_status') {
            const doc = await db.collection('stato del servizio').doc('current_status').get();
            return sendJson(res, 200, {
                data: doc.exists ? serializeData(doc.data()) : null
            });
        }

        if (action === 'configure_project_payment') {
            const userId = body.userId;
            if (!validDocumentId(userId)) {
                return sendJson(res, 400, { error: 'ID utente non valido.' });
            }

            const profileRef = db.collection('utenti_dashboard').doc(userId);
            const profileSnapshot = await profileRef.get();
            if (!profileSnapshot.exists) {
                return sendJson(res, 404, { error: 'Profilo cliente non trovato.' });
            }

            const totalEur = Number(body.totalEur);
            if (!Number.isFinite(totalEur) || totalEur <= 0 || Math.round(totalEur * 100) <= 0 || Math.abs(totalEur * 100 - Math.round(totalEur * 100)) > 0.00001) {
                return sendJson(res, 400, { error: 'Inserisci un totale progetto valido, in euro e con massimo due decimali.' });
            }
            const totalCents = Math.round(totalEur * 100);
            if (!Number.isSafeInteger(totalCents)) {
                return sendJson(res, 400, { error: 'Importo progetto troppo elevato.' });
            }
            if (totalCents < 4) {
                return sendJson(res, 400, { error: 'Il totale deve essere almeno €0,04 affinché tutte e tre le rate abbiano un importo positivo.' });
            }

            const requestedPlan = cleanString(body.plan, 30).toLowerCase();
            if (!['base', 'standard', 'premium'].includes(requestedPlan)) {
                return sendJson(res, 400, { error: 'Seleziona il piano Base, Standard o Premium.' });
            }

            const profile = profileSnapshot.data() || {};
            try {
                const authUser = await admin.auth().getUser(userId);
                if (authUser.disabled) return sendJson(res, 409, { error: 'L’account Firebase del cliente è disabilitato.' });
            } catch (error) {
                if (error.code === 'auth/user-not-found') return sendJson(res, 409, { error: 'Prima migra questo profilo collegandolo a un account Firebase Authentication.' });
                throw error;
            }
            const payments = profile.pagamenti || {};
            const currentProject = payments.progetto || {};
            const currentPhase = Number(currentProject.fase || 0);
            const currentTotal = Number(currentProject.totale_cent || 0);
            const oldRates = currentProject.rate || {};
            const anyPaid = ['rata_1', 'rata_2', 'rata_3'].some(key => oldRates[key]?.stato === 'paid');
            const checkoutStarted = ['rata_1', 'rata_2', 'rata_3'].some(key => oldRates[key]?.stato === 'checkout_pending');

            if (currentTotal > 0 && currentTotal !== totalCents && (currentPhase > 0 || anyPaid || checkoutStarted)) {
                return sendJson(res, 409, { error: 'Il totale non può essere modificato dopo l’avvio delle fasi o l’apertura di un pagamento. Contatta il supporto per una correzione controllata.' });
            }

            const firstCents = Math.round(totalCents * 0.20);
            const secondCents = Math.round(totalCents * 0.60);
            const thirdCents = totalCents - firstCents - secondCents;
            const amounts = [firstCents, secondCents, thirdCents];
            const rates = {};
            for (let index = 1; index <= 3; index++) {
                const key = `rata_${index}`;
                const oldRate = oldRates[key] || {};
                rates[key] = {
                    ...oldRate,
                    numero: index,
                    percentuale: [20, 60, 20][index - 1],
                    importo_cent: amounts[index - 1],
                    stato: oldRate.stato === 'paid'
                        ? 'paid'
                        : (currentPhase >= index ? (oldRate.stato || 'unlocked') : 'locked')
                };
            }

            const oldSubscription = payments.abbonamento || {};
            const subscriptionStatus = String(oldSubscription.stato || '').toLowerCase();
            if (oldSubscription.checkout_lock_id || (
                ['active', 'trialing', 'past_due', 'unpaid', 'incomplete', 'checkout_pending', 'in_attivazione'].includes(subscriptionStatus)
                && oldSubscription.piano_scelto !== requestedPlan
            )) {
                return sendJson(res, 409, { error: 'Il piano non può essere modificato mentre esiste un abbonamento in corso. Il cliente potrà cambiarlo dal portale Stripe.' });
            }

            const paidCents = ['rata_1', 'rata_2', 'rata_3'].reduce((sum, key) => {
                return sum + (rates[key]?.stato === 'paid' ? Number(rates[key].importo_cent || 0) : 0);
            }, 0);
            const project = {
                ...currentProject,
                fase: currentPhase,
                totale_cent: totalCents,
                valuta: 'eur',
                totale_pagato_cent: paidCents,
                residuo_cent: Math.max(0, totalCents - paidCents),
                rate: rates,
                ultimo_aggiornamento: admin.firestore.FieldValue.serverTimestamp()
            };
            const subscription = {
                ...oldSubscription,
                piano_scelto: requestedPlan,
                attivazione_abilitata: oldSubscription.attivazione_abilitata === true,
                stato: oldSubscription.stato || 'in_attesa'
            };

            await profileRef.set({
                pagamenti: { progetto: project, abbonamento: subscription },
                pagamenti_aggiornati_il: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });

            return sendJson(res, 200, {
                success: true,
                total_cents: totalCents,
                installments_cents: amounts,
                phase: currentPhase,
                plan: requestedPlan
            });
        }

        if (action === 'advance_project_phase') {
            const userId = body.userId;
            const targetPhase = Number(body.phase);
            if (!validDocumentId(userId)) {
                return sendJson(res, 400, { error: 'ID utente non valido.' });
            }
            if (![1, 2, 3].includes(targetPhase)) {
                return sendJson(res, 400, { error: 'Fase progetto non valida.' });
            }

            const profileRef = db.collection('utenti_dashboard').doc(userId);
            const snapshot = await profileRef.get();
            if (!snapshot.exists) return sendJson(res, 404, { error: 'Profilo cliente non trovato.' });
            const profile = snapshot.data() || {};
            try {
                const authUser = await admin.auth().getUser(userId);
                if (authUser.disabled) return sendJson(res, 409, { error: 'L’account Firebase del cliente è disabilitato.' });
            } catch (error) {
                if (error.code === 'auth/user-not-found') return sendJson(res, 409, { error: 'Prima migra questo profilo collegandolo a un account Firebase Authentication.' });
                throw error;
            }
            const payments = profile.pagamenti || {};
            const project = payments.progetto || {};
            const currentPhase = Number(project.fase || 0);
            if (Number(project.totale_cent || 0) <= 0) {
                return sendJson(res, 409, { error: 'Prima configura il totale del progetto.' });
            }
            if (targetPhase !== currentPhase + 1) {
                return sendJson(res, 409, { error: `Puoi attivare soltanto la fase ${currentPhase + 1}.` });
            }
            if (targetPhase > 1 && project.rate?.[`rata_${targetPhase - 1}`]?.stato !== 'paid') {
                return sendJson(res, 409, { error: `Per attivare la fase ${targetPhase} deve prima risultare pagata la rata ${targetPhase - 1}.` });
            }

            const rateKey = `rata_${targetPhase}`;
            await profileRef.update({
                'pagamenti.progetto.fase': targetPhase,
                [`pagamenti.progetto.rate.${rateKey}.stato`]: 'unlocked',
                [`pagamenti.progetto.rate.${rateKey}.sbloccata_il`]: admin.firestore.FieldValue.serverTimestamp(),
                'pagamenti.progetto.ultimo_aggiornamento': admin.firestore.FieldValue.serverTimestamp(),
                'pagamenti_aggiornati_il': admin.firestore.FieldValue.serverTimestamp()
            });
            return sendJson(res, 200, { success: true, phase: targetPhase, unlocked_installment: targetPhase });
        }

        if (action === 'enable_subscription_activation') {
            const userId = body.userId;
            if (!validDocumentId(userId)) {
                return sendJson(res, 400, { error: 'ID utente non valido.' });
            }
            const profileRef = db.collection('utenti_dashboard').doc(userId);
            const snapshot = await profileRef.get();
            if (!snapshot.exists) return sendJson(res, 404, { error: 'Profilo cliente non trovato.' });
            const profile = snapshot.data() || {};
            try {
                const authUser = await admin.auth().getUser(userId);
                if (authUser.disabled) return sendJson(res, 409, { error: 'L’account Firebase del cliente è disabilitato.' });
            } catch (error) {
                if (error.code === 'auth/user-not-found') return sendJson(res, 409, { error: 'Prima migra questo profilo collegandolo a un account Firebase Authentication.' });
                throw error;
            }
            const payments = profile.pagamenti || {};
            const project = payments.progetto || {};
            const subscription = payments.abbonamento || {};
            if (Number(project.fase || 0) !== 3 || project.rate?.rata_3?.stato !== 'paid') {
                return sendJson(res, 409, { error: 'Puoi abilitare l’abbonamento solo dopo la fase 3 e il pagamento della rata finale.' });
            }
            if (!['base', 'standard', 'premium'].includes(String(subscription.piano_scelto || '').toLowerCase())) {
                return sendJson(res, 409, { error: 'Prima seleziona il piano mensile del cliente.' });
            }
            await profileRef.update({
                'pagamenti.abbonamento.attivazione_abilitata': true,
                'pagamenti.abbonamento.stato': 'in_attesa_conferma_cliente',
                'pagamenti.abbonamento.attivazione_abilitata_il': admin.firestore.FieldValue.serverTimestamp(),
                'pagamenti_aggiornati_il': admin.firestore.FieldValue.serverTimestamp()
            });
            return sendJson(res, 200, { success: true, activation_enabled: true });
        }

        if (action === 'create_user') {
            const collectionName = cleanString(body.collection || 'utenti_dashboard', 100);
            if (collectionName !== 'utenti_dashboard') {
                return sendJson(res, 403, { error: 'Collezione non autorizzata' });
            }

            const uid = cleanString(body.uid, 150);
            if (!validDocumentId(uid)) {
                return sendJson(res, 400, { error: 'Inserisci un UID Firebase Authentication valido.' });
            }

            let authUser;
            try {
                authUser = await admin.auth().getUser(uid);
            } catch (error) {
                if (error.code === 'auth/user-not-found') {
                    return sendJson(res, 404, { error: 'UID non trovato in Firebase Authentication. Crea prima l’account cliente con una password temporanea.' });
                }
                throw error;
            }
            if (authUser.disabled || !authUser.email) {
                return sendJson(res, 400, { error: 'L’account Firebase deve essere attivo e avere un indirizzo email.' });
            }

            const email = authUser.email.trim().toLowerCase();
            const userData = pickUserFields(body.data, true);
            userData.email = email;

            const legacyUserId = cleanString(body.legacyUserId, 150);
            if (legacyUserId && !validDocumentId(legacyUserId)) {
                return sendJson(res, 400, { error: 'ID del vecchio documento non valido.' });
            }
            if (legacyUserId && legacyUserId === uid) {
                return sendJson(res, 400, { error: 'Il vecchio ID deve essere diverso dal nuovo UID.' });
            }

            const recoveryCodes = Array.isArray(body.recoveryCodes)
                ? body.recoveryCodes.map(code => cleanString(code, 30).replace(/[\s-]/g, '').toUpperCase())
                : [];
            if (
                recoveryCodes.length !== 8 ||
                new Set(recoveryCodes).size !== 8 ||
                recoveryCodes.some(code => !/^[A-F0-9]{12}$/.test(code))
            ) {
                return sendJson(res, 400, { error: 'Devi generare esattamente 8 codici di sicurezza validi e distinti.' });
            }

            const userRef = db.collection('utenti_dashboard').doc(uid);
            const existingUidDoc = await userRef.get();
            if (existingUidDoc.exists) {
                return sendJson(res, 409, { error: 'Esiste già un profilo CreatorWeb associato a questo UID.' });
            }

            let legacySnapshot = null;
            if (legacyUserId) {
                legacySnapshot = await db.collection('utenti_dashboard').doc(legacyUserId).get();
                if (!legacySnapshot.exists) {
                    return sendJson(res, 404, { error: 'Il vecchio documento indicato non esiste in utenti_dashboard.' });
                }
                const legacyRecord = legacySnapshot.data() || {};
                if (legacyRecord.migrated_to_uid && legacyRecord.migrated_to_uid !== uid) {
                    return sendJson(res, 409, { error: `Questo vecchio documento risulta già migrato sull’UID ${legacyRecord.migrated_to_uid}.` });
                }
                const legacyEmail = cleanString(legacyRecord.email, 254).toLowerCase();
                if (legacyEmail && legacyEmail !== email) {
                    return sendJson(res, 409, { error: 'L’email del vecchio documento non coincide con quella dell’account Firebase.' });
                }
            }

            const emailMatches = await db.collection('utenti_dashboard').where('email', '==', email).get();
            const duplicateEmail = emailMatches.docs.find(doc => doc.id !== legacyUserId && doc.id !== uid);
            if (duplicateEmail) {
                return sendJson(res, 409, { error: 'Questa email è presente in un altro profilo. Indica il relativo ID come vecchio documento da migrare.' });
            }

            if (legacySnapshot?.exists) {
                const legacyData = pickUserFields(legacySnapshot.data(), true);
                const requestedName = userData.nome;
                const requestedUsername = userData.nome_utente;
                Object.assign(userData, legacyData);
                userData.nome = requestedName || userData.nome;
                userData.nome_utente = requestedUsername || userData.nome_utente;
                userData.email = email;
            }

            if (!userData.nome_utente) {
                return sendJson(res, 400, { error: 'Il nome utente è obbligatorio.' });
            }
            userData.nome_utente = userData.nome_utente.toLowerCase();
            userData.nome = userData.nome || userData.nome_utente;
            userData.codici_sicurezza_hash = recoveryCodes.map(code =>
                crypto.createHash('sha256').update(code).digest('hex')
            );
            userData.codici_sicurezza_generati_il = admin.firestore.FieldValue.serverTimestamp();
            userData.data = admin.firestore.FieldValue.serverTimestamp();
            userData.account = {
                must_change_password: true,
                created_at: admin.firestore.FieldValue.serverTimestamp()
            };
            userData.migrated_from_legacy_id = legacyUserId || null;

            const usernameMatches = await db.collection('utenti_dashboard')
                .where('nome_utente', '==', userData.nome_utente)
                .get();
            const duplicateUsername = usernameMatches.docs.find(doc => doc.id !== legacyUserId && doc.id !== uid);
            if (duplicateUsername) {
                return sendJson(res, 409, { error: 'Questo nome utente è già utilizzato.' });
            }

            const batch = db.batch();
            batch.create(userRef, userData);

            let privateDataCopied = false;
            if (legacyUserId) {
                const legacyPrivateRef = db.collection('users').doc(legacyUserId);
                const legacyPrivateSnapshot = await legacyPrivateRef.get();
                if (legacyPrivateSnapshot.exists) {
                    const privateData = legacyPrivateSnapshot.data() || {};
                    batch.set(db.collection('users').doc(uid), {
                        ...privateData,
                        userid: uid,
                        migrated_from_legacy_id: legacyUserId,
                        migrated_at: admin.firestore.FieldValue.serverTimestamp()
                    }, { merge: true });
                    privateDataCopied = true;
                }
                batch.set(db.collection('utenti_dashboard').doc(legacyUserId), {
                    password: admin.firestore.FieldValue.delete(),
                    codici_sicurezza_hash: admin.firestore.FieldValue.delete(),
                    migrated_to_uid: uid,
                    migrated_at: admin.firestore.FieldValue.serverTimestamp()
                }, { merge: true });
            }

            await batch.commit();
            const stripeMappingCounts = {};
            const stripeMappingWarnings = [];
            let stripeEventCount = 0;
            if (legacyUserId) {
                for (const collectionName of ['stripeCustomers', 'stripeSubscriptions', 'stripeAccounts']) {
                    try {
                        const mappings = await db.collection(collectionName).where('userid', '==', legacyUserId).get();
                        stripeMappingCounts[collectionName] = mappings.size;
                        const writer = db.bulkWriter();
                        mappings.docs.forEach(mapping => writer.set(mapping.ref, {
                            userid: uid,
                            migrated_from_legacy_id: legacyUserId
                        }, { merge: true }));
                        await writer.close();
                    } catch (error) {
                        console.error(`Migrazione mapping ${collectionName} non riuscita:`, error);
                        stripeMappingWarnings.push(collectionName);
                    }
                }

                try {
                    const oldEvents = await db.collection('users').doc(legacyUserId)
                        .collection('stripeEvents').get();
                    stripeEventCount = oldEvents.size;
                    const writer = db.bulkWriter();
                    oldEvents.docs.forEach(eventDoc => writer.set(
                        db.collection('users').doc(uid).collection('stripeEvents').doc(eventDoc.id),
                        { ...eventDoc.data(), migrated_from_legacy_id: legacyUserId },
                        { merge: true }
                    ));
                    await writer.close();
                } catch (error) {
                    console.error('Migrazione storico eventi Stripe non riuscita:', error);
                    stripeMappingWarnings.push('users/{legacyId}/stripeEvents');
                }
            }

            return sendJson(res, 200, {
                success: true,
                uid,
                email,
                recovery_codes_saved: 8,
                migrated_legacy_profile: Boolean(legacySnapshot?.exists),
                migrated_private_data: privateDataCopied,
                migrated_stripe_mappings: stripeMappingCounts,
                migrated_stripe_events: stripeEventCount,
                stripe_mapping_warnings: stripeMappingWarnings
            });
        }

        if (action === 'update_user') {
            const collectionName = cleanString(body.collection || 'utenti_dashboard', 100);
            const userId = body.userId;

            if (collectionName !== 'utenti_dashboard') {
                return sendJson(res, 403, { error: 'Collezione non autorizzata' });
            }
            if (!validDocumentId(userId)) {
                return sendJson(res, 400, { error: 'ID utente non valido' });
            }

            const userRef = db.collection('utenti_dashboard').doc(userId);
            const existingProfile = await userRef.get();
            if (!existingProfile.exists) {
                return sendJson(res, 404, { error: 'Profilo utente non trovato' });
            }

            const cleanData = pickUserFields(body.data, false);
            if (Object.keys(cleanData).length === 0) {
                return sendJson(res, 400, { error: 'Nessun campo utente valido da aggiornare' });
            }

            if (typeof cleanData.email === 'string' && cleanData.email) {
                cleanData.email = cleanData.email.toLowerCase();
                try {
                    await admin.auth().getUser(userId);
                    await admin.auth().updateUser(userId, { email: cleanData.email });
                } catch (error) {
                    if (error.code !== 'auth/user-not-found') throw error;
                }
            }

            cleanData.ultimo_aggiornamento = admin.firestore.FieldValue.serverTimestamp();
            await userRef.set(cleanData, { merge: true });
            return sendJson(res, 200, { success: true });
        }

        if (action === 'update_cloudflare_config') {
            const userId = body.userId;
            const data = body.data && typeof body.data === 'object' ? body.data : {};

            if (!validDocumentId(userId)) {
                return sendJson(res, 400, { error: 'ID utente non valido' });
            }

            const apiToken = cleanString(
                data.api_token || data.apitoken_cf || '',
                1000
            );

            const accountId = cleanString(
                data.account_id || data.accid_cf || '',
                200
            );

            const zoneId = cleanString(
                data.zone_id || '',
                200
            );
            const hasChanges = Boolean(
                apiToken || accountId || zoneId ||
                data.clear_apitoken_cf === true ||
                data.clear_accid_cf === true ||
                data.clear_zone_id === true
            );

            if (!hasChanges) {
                return sendJson(res, 400, { error: 'Nessuna modifica Cloudflare da salvare' });
            }

            const userRef = db.collection('users').doc(userId);
            const snap = await userRef.get();
            const existing = snap.exists ? (snap.data() || {}) : {};
            const cloudflare = { ...(existing.cloudflare || {}) };

            if (!cloudflare.api_token && existing.apitoken_cf) cloudflare.api_token = existing.apitoken_cf;
            if (!cloudflare.account_id && existing.accid_cf) cloudflare.account_id = existing.accid_cf;
            if (!cloudflare.zone_id && existing.zone_id) cloudflare.zone_id = existing.zone_id;

            if (data.clear_apitoken_cf === true) delete cloudflare.api_token;
            else if (apiToken) cloudflare.api_token = apiToken;

            if (data.clear_accid_cf === true) delete cloudflare.account_id;
            else if (accountId) cloudflare.account_id = accountId;

            if (data.clear_zone_id === true) delete cloudflare.zone_id;
            else if (zoneId) cloudflare.zone_id = zoneId;

            await userRef.set({ cloudflare }, { merge: true });
            const savedSnapshot = await userRef.get();
            
            const savedCloudflare = savedSnapshot.exists
                ? savedSnapshot.data().cloudflare || {}
                : {};
            
            const missingFields = [
                'api_token',
                'account_id',
                'zone_id'
            ].filter(field => !savedCloudflare[field]);
            
            return sendJson(res, 200, {
                success: true,
                config_complete: missingFields.length === 0,
                missing_fields: missingFields
            });
            
            return sendJson(res, 200, { success: true });
        }

        if (action === 'delete_support_request') {
            const requestId = body.requestId;
            if (!validDocumentId(requestId)) {
                return sendJson(res, 400, { error: 'ID richiesta non valido' });
            }

            const ref = db.collection('richieste_supporto').doc(requestId);
            const snapshot = await ref.get();
            if (!snapshot.exists) {
                return sendJson(res, 404, { error: 'Richiesta non trovata' });
            }

            await ref.delete();
            return sendJson(res, 200, { success: true, message: 'Richiesta eliminata' });
        }

        if (action === 'update_status') {
            const stato = cleanString(body.stato, 100).toLowerCase();
            if (!STATUS_VALUES.has(stato)) {
                return sendJson(res, 400, { error: 'Stato del servizio non valido' });
            }

            const updatePayload = {
                stato,
                status: stato,
                ultimo_aggiornamento: admin.firestore.FieldValue.serverTimestamp()
            };

            if (body.messaggio !== undefined) {
                updatePayload.messaggio = cleanString(body.messaggio, 3000);
            }
            if (body.link_responsabilita !== undefined) {
                const link = cleanString(body.link_responsabilita, 2000);
                if (link && !/^https:\/\//i.test(link)) {
                    return sendJson(res, 400, { error: 'Il link deve iniziare con https://' });
                }
                updatePayload.link_responsabilita = link || null;
            }

            await db.collection('stato del servizio').doc('current_status').set(updatePayload, { merge: true });
            return sendJson(res, 200, { success: true });
        }

        return sendJson(res, 400, { error: 'Azione non riconosciuta' });

    } catch (error) {
        console.error('Admin API error:', error);
        return sendJson(res, error.status || 500, {
            error: error.status ? error.message : 'Errore interno del server'
        });
    }
};

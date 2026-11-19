const admin = require('firebase-admin');
const { JWT } = require('google-auth-library');

if (!admin.apps.length) {
    const rawServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;

    if (!rawServiceAccount) {
        throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_WORK');
    }

    const serviceAccount = typeof rawServiceAccount === 'string'
        ? JSON.parse(rawServiceAccount)
        : rawServiceAccount;

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();

const ALLOWED_ORIGINS = new Set([
    'https://creatorweb.cc',
    'https://www.creatorweb.cc'
]);

function sendJson(res, status, body) {
    return res.status(status).json(body);
}

function setCors(req, res) {
    const origin = req.headers.origin;

    if (origin && ALLOWED_ORIGINS.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400');
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'no-store, max-age=0');
}

function getRange(value) {
    return ['7d', '30d', '90d'].includes(value) ? value : '30d';
}

function getDateString(date) {
    return date.toISOString().slice(0, 10);
}

function createDateList(startDate, endDate) {
    const dates = [];

    for (
        let time = startDate.getTime();
        time <= endDate.getTime();
        time += 86400000
    ) {
        dates.push(getDateString(new Date(time)));
    }

    return dates;
}

async function readMetric(
    client,
    projectId,
    databaseId,
    metricType,
    startTime,
    endTime
) {
    const dailyValues = new Map();

    const filter = [
        `metric.type = "${metricType}"`,
        'resource.type = "firestore.googleapis.com/Database"',
        `resource.labels.database_id = "${databaseId}"`
    ].join(' AND ');

    let pageToken = '';

    do {
        const url = new URL(
            `https://monitoring.googleapis.com/v3/projects/${encodeURIComponent(projectId)}/timeSeries`
        );

        url.searchParams.set('filter', filter);
        url.searchParams.set('interval.startTime', startTime);
        url.searchParams.set('interval.endTime', endTime);
        url.searchParams.set('aggregation.alignmentPeriod', '86400s');
        url.searchParams.set('aggregation.perSeriesAligner', 'ALIGN_SUM');
        url.searchParams.set('view', 'FULL');
        url.searchParams.set('pageSize', '100000');

        if (pageToken) {
            url.searchParams.set('pageToken', pageToken);
        }

        const response = await client.request({
            url: url.toString(),
            method: 'GET'
        });

        const timeSeries = response.data.timeSeries || [];

        for (const timeSerie of timeSeries) {
            for (const point of (timeSerie.points || [])) {
                const interval = point.interval || {};

                const timestamp = interval.startTime
                    ? new Date(interval.startTime)
                    : new Date(
                        new Date(interval.endTime).getTime() - 1
                    );

                if (!Number.isFinite(timestamp.getTime())) continue;

                const date = getDateString(timestamp);

                const rawValue =
                    point.value?.int64Value ??
                    point.value?.doubleValue ??
                    0;

                const value = Number(rawValue);

                if (!Number.isFinite(value)) continue;

                dailyValues.set(
                    date,
                    (dailyValues.get(date) || 0) + value
                );
            }
        }

        pageToken = response.data.nextPageToken || '';
    } while (pageToken);

    return dailyValues;
}

module.exports = async function handler(req, res) {
    setCors(req, res);

    const origin = req.headers.origin;

    if (origin && !ALLOWED_ORIGINS.has(origin)) {
        return sendJson(res, 403, { error: 'Origin non autorizzata.' });
    }

    if (req.method === 'OPTIONS') {
        return res.status(204).end();
    }

    if (req.method !== 'GET') {
        return sendJson(res, 405, { error: 'Metodo non consentito.' });
    }

    try {
        const authorization = req.headers.authorization || '';
        const match = authorization.match(/^Bearer\s+(.+)$/i);

        if (!match) {
            return sendJson(res, 401, {
                error: 'Autenticazione richiesta.'
            });
        }

        let decoded;

        try {
            decoded = await admin.auth().verifyIdToken(match[1], true);
        } catch (_error) {
            return sendJson(res, 401, {
                error: 'Sessione non valida o scaduta.'
            });
        }

        const userId = decoded.uid;

        const profileSnap = await db
            .collection('utenti_dashboard')
            .doc(userId)
            .get();

        if (!profileSnap.exists) {
            return sendJson(res, 404, {
                error: 'Profilo cliente non trovato.'
            });
        }

        const profile = profileSnap.data() || {};
        const accessMode = String(profile.stats_access_mode || 'automatico');
        const phase = Number(profile.pagamenti?.progetto?.fase ?? 0);

        const statsAllowed =
            accessMode === 'mostra' ||
            (
                accessMode !== 'nascondi' &&
                Number.isFinite(phase) &&
                phase >= 3
            );

        if (!statsAllowed) {
            return sendJson(res, 403, {
                error: 'L’accesso alle statistiche non è abilitato.'
            });
        }

        const privateSnap = await db
            .collection('users')
            .doc(userId)
            .get();

        const config = privateSnap.exists
            ? (privateSnap.data().firestore || {})
            : {};

        if (config.enabled !== true) {
            return sendJson(res, 200, {
                enabled: false
            });
        }

        const projectId = String(config.project_id || '').trim();
        const databaseId = String(config.database_id || '(default)').trim();
        const serviceAccount = config.service_account || {};

        if (
            !projectId ||
            !serviceAccount.client_email ||
            !serviceAccount.private_key ||
            serviceAccount.project_id !== projectId
        ) {
            return sendJson(res, 409, {
                error: 'Configurazione Firestore incompleta. Verifica la pagina privata.'
            });
        }

        const privateKey = String(serviceAccount.private_key)
            .replace(/\\n/g, '\n');

        const client = new JWT({
            email: serviceAccount.client_email,
            key: privateKey,
            scopes: [
                'https://www.googleapis.com/auth/monitoring.read'
            ]
        });

        const range = getRange(req.query.range);

        const days = Number(range.replace('d', ''));
        const now = new Date();

        const startDate = new Date(Date.UTC(
            now.getUTCFullYear(),
            now.getUTCMonth(),
            now.getUTCDate() - days + 1
        ));

        const startTime = startDate.toISOString();
        const endTime = now.toISOString();

        const [readsMap, writesMap, deletesMap] = await Promise.all([
            readMetric(
                client,
                projectId,
                databaseId,
                'firestore.googleapis.com/document/read_ops_count',
                startTime,
                endTime
            ),
            readMetric(
                client,
                projectId,
                databaseId,
                'firestore.googleapis.com/document/write_ops_count',
                startTime,
                endTime
            ),
            readMetric(
                client,
                projectId,
                databaseId,
                'firestore.googleapis.com/document/delete_ops_count',
                startTime,
                endTime
            )
        ]);

        const dates = createDateList(
            startDate,
            new Date(Date.UTC(
                now.getUTCFullYear(),
                now.getUTCMonth(),
                now.getUTCDate()
            ))
        );

        const series = dates.map(date => ({
            date,
            reads: readsMap.get(date) || 0,
            writes: writesMap.get(date) || 0,
            deletes: deletesMap.get(date) || 0
        }));

        const summary = series.reduce((total, item) => {
            total.reads += item.reads;
            total.writes += item.writes;
            total.deletes += item.deletes;
            return total;
        }, {
            reads: 0,
            writes: 0,
            deletes: 0
        });

        return sendJson(res, 200, {
            success: true,
            enabled: true,
            project_id: projectId,
            database_id: databaseId,
            range,
            updated_at: new Date().toISOString(),
            summary,
            series
        });

    } catch (error) {
        console.error(
            'Firestore statistics API error:',
            error.response?.data || error.message
        );

        const googleStatus = error.response?.status || error.status;

        if (googleStatus === 403) {
            return sendJson(res, 502, {
                error: 'Google Cloud ha negato l’accesso. Controlla che Cloud Monitoring API sia attiva e che il Service Account abbia il ruolo Monitoring Viewer.'
            });
        }

        if (googleStatus === 401) {
            return sendJson(res, 502, {
                error: 'Le credenziali del Service Account non sono valide.'
            });
        }

        return sendJson(res, 500, {
            error: 'Errore durante il recupero delle statistiche Firestore.'
        });
    }
};

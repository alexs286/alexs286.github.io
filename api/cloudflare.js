const admin = require("firebase-admin");
const dns = require("node:dns").promises;
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");

const ALLOWED_ORIGIN = "https://www.creatorweb.cc";
const GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql";
const ALLOWED_RANGES = new Set(["7d", "30d", "90d"]);
const RATE_LIMIT_WINDOW_MS = 60000;
const RATE_LIMIT_MAX = 30;
const rateLimits = new Map();

if (!admin.apps.length) {
    const serviceAccountValue = process.env.FIREBASE_SERVICE_ACCOUNT_WORK;

    if (!serviceAccountValue) {
        throw new Error("Missing FIREBASE_SERVICE_ACCOUNT_WORK");
    }

    admin.initializeApp({
        credential: admin.credential.cert(JSON.parse(serviceAccountValue))
    });
}

const db = admin.firestore();


const ZONE_ANALYTICS_QUERY = `
query CreatorWebZoneAnalytics($zoneTag: string, $start: Date, $end: Date) {
    viewer {
        zones(filter: { zoneTag: $zoneTag }) {
            httpRequests1dGroups(
                limit: 100
                orderBy: [date_ASC]
                filter: {
                    date_geq: $start
                    date_lt: $end
                }
            ) {
                dimensions {
                    date
                }
                sum {
                    requests
                    bytes
                    pageViews
                    countryMap {
                        clientCountryName
                        requests
                    }
                }
                uniq {
                    uniques
                }
            }
        }
    }
}`;


const WORKERS_ANALYTICS_QUERY = `
query CreatorWebWorkersAnalytics($accountTag: string, $start: string, $end: string) {
    viewer {
        accounts(filter: { accountTag: $accountTag }) {
            workersInvocationsAdaptive(
                limit: 1
                filter: {
                    datetime_geq: $start
                    datetime_leq: $end
                }
            ) {
                sum {
                    requests
                    errors
                }
            }
        }
    }
}`;

function setCors(req, res) {
    const origin = req.headers.origin;

    if (!origin || origin === ALLOWED_ORIGIN) {
        res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    }

    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Max-Age", "86400");
    res.setHeader("Vary", "Origin");
    res.setHeader("Cache-Control", "no-store, max-age=0");
}

function sendJson(res, status, body) {
    return res.status(status).json(body);
}

function getUserId(req) {
    const raw = req.query?.userId;

    if (typeof raw !== "string") return null;

    const value = raw.trim();

    if (!value || value.length > 150 || value.includes("/")) {
        return null;
    }

    return value;
}

function checkRateLimit(req) {
    const forwarded = req.headers["x-forwarded-for"];

    const ip =
        (typeof forwarded === "string"
            ? forwarded.split(",")[0].trim()
            : "") ||
        req.socket?.remoteAddress ||
        "unknown";

    const now = Date.now();

    const current = rateLimits.get(ip) || {
        count: 0,
        startedAt: now
    };

    if (now - current.startedAt >= RATE_LIMIT_WINDOW_MS) {
        current.count = 0;
        current.startedAt = now;
    }

    current.count++;
    rateLimits.set(ip, current);

    if (rateLimits.size > 5000) {
        for (const [key, value] of rateLimits) {
            if (now - value.startedAt >= RATE_LIMIT_WINDOW_MS) {
                rateLimits.delete(key);
            }
        }
    }

    return current.count > RATE_LIMIT_MAX;
}

function toNumber(value) {
    const number = Number(value ?? 0);
    return Number.isFinite(number) ? number : 0;
}

function getCloudflareConfig(user) {
    return {
        apiToken: user?.apitoken_cf || null,
        accountId: user?.accid_cf || null,
        zoneId: user?.zone_id || null
    };
}


function getRangeDates(range) {
    const days = Number(range.slice(0, -1));

    const now = new Date();
    const start = new Date(now);

    start.setUTCDate(start.getUTCDate() - (days - 1));

    const end = new Date(now);
    end.setUTCDate(end.getUTCDate() + 1);

    return {
        start: start.toISOString().slice(0, 10),
        end: end.toISOString().slice(0, 10),
        startDateTime: start.toISOString(),
        endDateTime: now.toISOString()
    };
}

async function cloudflareGraphQL(apiToken, query, variables) {
    const controller = new AbortController();

    const timeout = setTimeout(
        () => controller.abort(),
        18000
    );

    try {
        const response = await fetch(GRAPHQL_URL, {
            method: "POST",

            headers: {
                Authorization: `Bearer ${apiToken}`,
                "Content-Type": "application/json",
                Accept: "application/json"
            },

            body: JSON.stringify({
                query,
                variables
            }),

            signal: controller.signal
        });

        const payload = await response.json().catch(() => ({}));

        const errors = Array.isArray(payload.errors)
            ? payload.errors
            : [];

        if (!response.ok || errors.length > 0) {
            throw new Error(
                errors.map(item => item.message).filter(Boolean).join("; ") ||
                `Cloudflare HTTP ${response.status}`
            );
        }

        if (!payload.data) {
            throw new Error("Cloudflare returned an empty response");
        }

        return payload.data;

    } finally {
        clearTimeout(timeout);
    }
}

function normalizeAnalytics(records) {
    const series = (Array.isArray(records) ? records : [])
        .map(record => {
            const sum = record.sum || {};

            return {
                date: record.dimensions?.date || null,
                requests: toNumber(sum.requests),
                pageviews: toNumber(sum.pageViews),
                unique_visitors: toNumber(record.uniq?.uniques),
                bandwidth_bytes: toNumber(sum.bytes),

                countries: Array.isArray(sum.countryMap)
                    ? sum.countryMap.map(country => ({
                        name: country.clientCountryName || "Altro",
                        requests: toNumber(country.requests)
                    }))
                    : []
            };
        })
        .filter(row => row.date);

    const countryTotals = new Map();

    for (const day of series) {
        for (const country of day.countries) {
            countryTotals.set(
                country.name,
                (countryTotals.get(country.name) || 0) + country.requests
            );
        }
    }

    return {
        summary: {
            requests: series.reduce(
                (total, row) => total + row.requests,
                0
            ),

            pageviews: series.reduce(
                (total, row) => total + row.pageviews,
                0
            ),

            unique_visitors: series.reduce(
                (total, row) => total + row.unique_visitors,
                0
            ),

            bandwidth_bytes: series.reduce(
                (total, row) => total + row.bandwidth_bytes,
                0
            )
        },

        series: series.map(({ countries, ...row }) => row),

        breakdown: {
            countries: Array.from(countryTotals.entries())
                .map(([name, value]) => ({
                    name,
                    value
                }))
                .sort((a, b) => b.value - a.value)
                .slice(0, 10)
        }
    };
}

async function getWorkersMetrics(apiToken, accountId, dates) {
    if (!accountId) return null;

    try {
        const data = await cloudflareGraphQL(
            apiToken,
            WORKERS_ANALYTICS_QUERY,
            {
                accountTag: accountId,
                start: dates.startDateTime,
                end: dates.endDateTime
            }
        );

        const row =
            data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive?.[0];

        if (!row) {
            return {
                requests: 0,
                errors: 0
            };
        }

        return {
            requests: toNumber(row.sum?.requests),
            errors: toNumber(row.sum?.errors)
        };

    } catch (error) {
        console.warn(
            "Cloudflare Workers metrics unavailable:",
            error.message
        );

        return null;
    }
}

function isPrivateIPv4(address) {
    const parts = address.split(".").map(Number);

    if (
        parts.length !== 4 ||
        parts.some(part =>
            !Number.isInteger(part) ||
            part < 0 ||
            part > 255
        )
    ) {
        return true;
    }

    const [a, b, c] = parts;

    return a === 0 ||
        a === 10 ||
        a === 127 ||
        a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 192 && b === 0) ||
        (a === 192 && b === 88 && c === 99) ||
        (a === 198 && (b === 18 || b === 19 || b === 51)) ||
        (a === 203 && b === 0 && c === 113);
}

function isPublicIp(address) {
    const family = net.isIP(address);

    if (family === 4) {
        return !isPrivateIPv4(address);
    }

    if (family !== 6) return false;

    const value = address.toLowerCase();

    if (value.startsWith("::ffff:")) {
        const mapped = value.slice(7);

        return net.isIP(mapped) === 4 &&
            !isPrivateIPv4(mapped);
    }

    return !value.startsWith("::") &&
        !value.startsWith("fc") &&
        !value.startsWith("fd") &&
        !/^fe[89ab]/.test(value) &&
        !value.startsWith("ff") &&
        !value.startsWith("2001:db8");
}

async function resolvePublicHost(hostname) {
    const host = hostname.toLowerCase();

    if (
        !host ||
        host === "localhost" ||
        host.endsWith(".localhost") ||
        host.endsWith(".local") ||
        host.endsWith(".internal") ||
        net.isIP(host)
    ) {
        throw new Error("Invalid public hostname");
    }

    const records = await dns.lookup(host, {
        all: true,
        verbatim: true
    });

    if (
        !records.length ||
        records.some(record => !isPublicIp(record.address))
    ) {
        throw new Error(
            "Hostname does not resolve exclusively to public IP addresses"
        );
    }

    return records[0];
}

function requestWebsite(url, resolvedAddress, method) {
    return new Promise((resolve, reject) => {
        const transport =
            url.protocol === "https:" ? https : http;

        const request = transport.request({
            protocol: url.protocol,
            hostname: url.hostname,
            port: url.port || undefined,
            path: `${url.pathname}${url.search}`,
            method,

            headers: {
                Host: url.host,
                "User-Agent": "CreatorWeb-Uptime-Check/1.0",

                ...(method === "GET"
                    ? { Range: "bytes=0-0" }
                    : {})
            },

            servername: url.hostname,

            lookup: (_hostname, _options, callback) => {
                callback(
                    null,
                    resolvedAddress.address,
                    resolvedAddress.family
                );
            },

            timeout: 7000

        }, response => {
            response.resume();

            resolve({
                statusCode: response.statusCode || 0,
                location: response.headers.location || null
            });
        });

        request.on("timeout", () => {
            request.destroy(new Error("Website check timed out"));
        });

        request.on("error", reject);
        request.end();
    });
}

async function checkWebsite(rawUrl) {
    let currentUrl;

    try {
        currentUrl = new URL(
            /^https?:\/\//i.test(rawUrl)
                ? rawUrl
                : `https://${rawUrl}`
        );
    } catch {
        throw new Error("Invalid website URL");
    }

    for (let redirects = 0; redirects <= 4; redirects++) {
        if (
            !["http:", "https:"].includes(currentUrl.protocol) ||
            currentUrl.username ||
            currentUrl.password
        ) {
            throw new Error("Unsupported website URL");
        }

        const address = await resolvePublicHost(
            currentUrl.hostname
        );

        let result = await requestWebsite(
            currentUrl,
            address,
            "HEAD"
        );

        if (
            result.statusCode === 405 ||
            result.statusCode === 501
        ) {
            result = await requestWebsite(
                currentUrl,
                address,
                "GET"
            );
        }

        if (
            result.statusCode >= 300 &&
            result.statusCode < 400 &&
            result.location
        ) {
            if (redirects === 4) {
                throw new Error("Too many redirects");
            }

            currentUrl = new URL(
                result.location,
                currentUrl
            );

            continue;
        }

        return {
            online:
                result.statusCode > 0 &&
                result.statusCode < 500,

            status_code: result.statusCode,
            checked_at: new Date().toISOString()
        };
    }

    throw new Error("Website check failed");
}

async function handleStats(req, res, userId) {
    const rangeParam = req.query?.range;

    const range =
        typeof rangeParam === "string" &&
        ALLOWED_RANGES.has(rangeParam)
            ? rangeParam
            : "30d";

    const [privateSnapshot, dashboardSnapshot] =
        await Promise.all([
            db.collection("users").doc(userId).get(),
            db.collection("utenti_dashboard").doc(userId).get()
        ]);

    if (!dashboardSnapshot.exists && !privateSnapshot.exists) {
        return sendJson(res, 404, {
            success: false,
            error: "User not found"
        });
    }

    const privateUser = privateSnapshot.exists
        ? privateSnapshot.data() || {}
        : {};

    const cloudflare = getCloudflareConfig(privateUser);

    if (
        !cloudflare.apiToken ||
        !cloudflare.accountId ||
        !cloudflare.zoneId
    ) {
        return sendJson(res, 409, {
            success: false,
            error: "Cloudflare configuration incomplete",

            required_fields: [
                "users/{userId}.cloudflare.api_token",
                "users/{userId}.cloudflare.account_id",
                "users/{userId}.cloudflare.zone_id"
            ]
        });
    }

    const dates = getRangeDates(range);

    const data = await cloudflareGraphQL(
        cloudflare.apiToken,
        ZONE_ANALYTICS_QUERY,
        {
            zoneTag: cloudflare.zoneId,
            start: dates.start,
            end: dates.end
        }
    );

    const zone = data?.viewer?.zones?.[0];

    if (!zone) {
        return sendJson(res, 502, {
            success: false,
            error: "No analytics data returned for this Cloudflare zone"
        });
    }

    const analytics = normalizeAnalytics(
        zone.httpRequests1dGroups
    );

    const workers = await getWorkersMetrics(
        cloudflare.apiToken,
        cloudflare.accountId,
        dates
    );

    return sendJson(res, 200, {
        success: true,
        range,
        summary: analytics.summary,
        series: analytics.series,
        breakdown: analytics.breakdown,
        workers,

        unique_visitors_note:
            "Somma dei visitatori unici giornalieri; uno stesso visitatore può essere contato in più giorni.",

        updated_at: new Date().toISOString()
    });
}


async function handleSiteStatus(res, userId) {
    const [dashboardSnapshot, privateSnapshot] =
        await Promise.all([
            db.collection("utenti_dashboard").doc(userId).get(),
            db.collection("users").doc(userId).get()
        ]);

    const dashboardUser = dashboardSnapshot.exists
        ? dashboardSnapshot.data() || {}
        : {};

    const privateUser = privateSnapshot.exists
        ? privateSnapshot.data() || {}
        : {};

    const websiteUrl =
        dashboardUser.url_sito ||
        privateUser.url_sito ||
        null;

    if (!websiteUrl) {
        return sendJson(res, 200, {
            online: false,
            configured: false,
            checked_at: new Date().toISOString()
        });
    }

    try {
        const result = await checkWebsite(String(websiteUrl));

        return sendJson(res, 200, {
            ...result,
            configured: true
        });

    } catch (error) {
        console.warn(
            "Website availability check failed:",
            error.message
        );

        return sendJson(res, 200, {
            online: false,
            configured: true,
            checked_at: new Date().toISOString(),
            reason: "unreachable"
        });
    }
}


module.exports = async (req, res) => {
    setCors(req, res);

    if (req.method === "OPTIONS") {
        return res.status(204).end();
    }

    if (req.method !== "GET") {
        return sendJson(res, 405, {
            success: false,
            error: "Method not allowed"
        });
    }

    if (
        req.headers.origin &&
        req.headers.origin !== ALLOWED_ORIGIN
    ) {
        return sendJson(res, 403, {
            success: false,
            error: "Origin not allowed"
        });
    }

    if (checkRateLimit(req)) {
        return sendJson(res, 429, {
            success: false,
            error: "Too many requests"
        });
    }

    const userId = getUserId(req);

    if (!userId) {
        return sendJson(res, 400, {
            success: false,
            error: "Missing or invalid userId"
        });
    }

    const action =
        typeof req.query?.action === "string"
            ? req.query.action
            : "stats";

    try {
        if (action === "stats") {
            return await handleStats(req, res, userId);
        }

        if (action === "site-status") {
            return await handleSiteStatus(res, userId);
        }

        return sendJson(res, 400, {
            success: false,
            error: "Unknown action"
        });


    } catch (error) {
        console.error("Cloudflare API error:", {
            message: error.message,
            stack: error.stack
        });
    
        return sendJson(res, 502, {
            success: false,
            error: action === "stats"
                ? "Unable to retrieve Cloudflare statistics"
                : "Unable to check website availability",
            details: error.message
        });
    }
};

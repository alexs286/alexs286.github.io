import { GoogleGenerativeAI } from "@google/generative-ai";

const allowedOrigins = new Set([
  "https://www.alexs286.github.io",
  "https://alexs286.github.io"
]);

const RATE_WINDOW = 60 * 1000;
const RATE_LIMIT = 20;
const BURST_WINDOW = 10 * 1000;
const BURST_LIMIT = 5;
const MAX_BODY_BYTES = 900000;
const MAX_CODE_CHARS = 700000;
const MAX_IDEA_CHARS = 30000;
const MAX_DIRECTIVES_CHARS = 30000;
const MAX_FEATURES_CHARS = 30000;
const REQUEST_TIMEOUT = 90000;

const rateStore = globalThis.__AI_FORGE_RATE_STORE || new Map();
const activeStore = globalThis.__AI_FORGE_ACTIVE_STORE || new Map();

globalThis.__AI_FORGE_RATE_STORE = rateStore;
globalThis.__AI_FORGE_ACTIVE_STORE = activeStore;

function getOrigin(req) {
  return req.headers.origin || "";
}

function getClientIp(req) {
  const trusted =
    req.headers["x-vercel-forwarded-for"] ||
    req.headers["x-forwarded-for"] ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "unknown";

  return String(trusted).split(",")[0].trim();
}

function getRequestSize(req) {
  const value = req.headers["content-length"];
  if (!value) return 0;

  const size = Number(value);

  return Number.isFinite(size) ? size : 0;
}

function json(res, status, data) {
  res.status(status).json(data);
}

function cleanupRateStore(now) {
  for (const [ip, data] of rateStore) {
    if (
      now - data.windowStart > RATE_WINDOW &&
      now - data.burstStart > BURST_WINDOW
    ) {
      rateStore.delete(ip);
    }
  }
}

function checkRateLimit(ip) {
  const now = Date.now();

  cleanupRateStore(now);

  let data = rateStore.get(ip);

  if (!data) {
    data = {
      windowStart: now,
      windowCount: 0,
      burstStart: now,
      burstCount: 0
    };

    rateStore.set(ip, data);
  }

  if (now - data.windowStart >= RATE_WINDOW) {
    data.windowStart = now;
    data.windowCount = 0;
  }

  if (now - data.burstStart >= BURST_WINDOW) {
    data.burstStart = now;
    data.burstCount = 0;
  }

  data.windowCount++;
  data.burstCount++;

  if (data.windowCount > RATE_LIMIT) {
    return {
      allowed: false,
      retryAfter: Math.ceil(
        (RATE_WINDOW - (now - data.windowStart)) / 1000
      )
    };
  }

  if (data.burstCount > BURST_LIMIT) {
    return {
      allowed: false,
      retryAfter: Math.ceil(
        (BURST_WINDOW - (now - data.burstStart)) / 1000
      )
    };
  }

  return {
    allowed: true,
    retryAfter: 0
  };
}

function validateString(value, max, name) {
  if (value === undefined || value === null) return "";

  if (typeof value !== "string") {
    throw new Error(`${name} non valido`);
  }

  if (value.length > max) {
    throw new Error(`${name} troppo lungo`);
  }

  return value;
}

function validateBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("Body non valido");
  }

  const type = validateString(body.type, 30, "type");
  const mode = validateString(body.mode, 30, "mode");

  const idea = validateString(
    body.idea,
    MAX_IDEA_CHARS,
    "idea"
  );

  const code = validateString(
    body.code,
    MAX_CODE_CHARS,
    "code"
  );

  const directives = validateString(
    body.directives,
    MAX_DIRECTIVES_CHARS,
    "directives"
  );

  const previousCode = validateString(
    body.previousCode,
    MAX_CODE_CHARS,
    "previousCode"
  );

  const prompt = validateString(
    body.prompt,
    MAX_IDEA_CHARS,
    "prompt"
  );

  let features = body.features ?? [];

  if (!Array.isArray(features)) {
    throw new Error("features non valido");
  }

  const featuresText = JSON.stringify(features);

  if (featuresText.length > MAX_FEATURES_CHARS) {
    throw new Error("features troppo grandi");
  }

  if (!["analyze", "generate", "regenerate", "auto"].includes(type)) {
    throw new Error("Tipo di richiesta non valido");
  }

  if (!["create", "evolve"].includes(mode)) {
    throw new Error("Modalità non valida");
  }

  return {
    type,
    mode,
    idea,
    code,
    directives,
    previousCode,
    prompt,
    features
  };
}

function buildSystemRules(mode, type) {
  return `
Sei il motore AI di AI Site Forge.

REGOLE FONDAMENTALI:

1. Devi preservare ciò che esiste già.
2. Non eliminare funzioni esistenti per fare spazio a funzioni nuove.
3. Non riscrivere inutilmente il sito.
4. Preferisci sempre modifiche incrementali.
5. CSS mezzo compatto.
6. ZERO commenti nel codice.
7. Non aggiungere commenti HTML.
8. Non aggiungere commenti CSS.
9. Non aggiungere commenti JavaScript.
10. Mantieni HTML, CSS e JS compatibili con il progetto esistente.
11. Usa funzioni JavaScript nominate.
12. Quando migliori una funzione esistente, mantieni ESATTAMENTE lo stesso nome.
13. La funzione migliorata deve poter sostituire quella precedente.
14. Non modificare il nome di una funzione solamente per introdurre un miglioramento.
15. Quando aggiungi una nuova funzione, rendila autonoma e facilmente integrabile.
16. Evita duplicazioni.
17. Non usare dipendenze esterne senza reale necessità.
18. Non inserire chiavi API, token, password o segreti nel frontend.
19. Quando è necessario il backend, indica chiaramente quale endpoint serve.
20. Non restituire mai l'intero sito quando è sufficiente una modifica locale.
21. Non rimuovere codice funzionante solamente perché esiste un modo diverso per implementare la stessa funzione.
22. Mantieni la compatibilità con le funzioni precedentemente create.

MODALITÀ ATTUALE:
${mode}

TIPO DI OPERAZIONE:
${type}
`;
}

function buildPrompt(body) {
  const {
    type,
    mode,
    idea,
    code,
    directives,
    previousCode,
    features,
    prompt
  } = body;

  const rules = buildSystemRules(mode, type);

  if (type === "analyze") {
    return `${rules}

Devi analizzare il progetto.

Non generare ancora il codice completo.

Individua:
- funzioni utili
- dettagli importanti
- possibili miglioramenti
- elementi modulari
- eventuali API necessarie

Restituisci una risposta testuale libera, chiara e strutturata.

Non usare JSON obbligatoriamente.
Non usare markdown obbligatoriamente.

IDEA:
${idea}

CODICE ESISTENTE:
${code}

DIRETTIVE:
${directives}

RICHIESTA AGGIUNTIVA:
${prompt}`;
  }

  if (type === "generate") {
    return `${rules}

Devi generare il primo sito.

In questa fase puoi generare il codice completo index.html perché questa è la base iniziale del progetto.

Il file deve contenere:
- HTML
- CSS
- JavaScript

tutto nello stesso index.html.

Il risultato deve essere pensato fin dall'inizio per essere evoluto successivamente.

CREA UNA BASE MODULARE.

FUNZIONI SELEZIONATE:
${JSON.stringify(features, null, 2)}

IDEA:
${idea}

CODICE PRECEDENTE:
${previousCode || code}

DIRETTIVE:
${directives}

Restituisci direttamente il risultato utile.
Non inventare uno schema JSON obbligatorio.
`;
  }

  if (type === "regenerate") {
    return `${rules}

Devi evolvere un sito esistente.

IMPORTANTE:

NON restituire automaticamente l'intero index.html.

Devi restituire SOLTANTO:
1. nuove parti di codice da aggiungere
2. funzioni esistenti da sostituire
3. eventuali piccole modifiche necessarie per collegare le nuove parti

Quando devi modificare una funzione esistente usa questo formato:

=== REPLACE FUNCTION: nomeFunzione ===

[nuova versione completa della funzione]

=== END FUNCTION ===

Il nome della funzione deve essere identico a quello già presente.

Per nuove parti usa:

=== ADD ===

[nuovo codice]

=== END ADD ===

Ogni blocco deve essere autonomo e facilmente inseribile.

Non riscrivere l'intero sito.
Non eliminare funzioni.
Non sostituire codice non necessario.
Non modificare arbitrariamente parti esistenti.

CODICE ATTUALE:
${code || previousCode}

IDEA ORIGINALE:
${idea}

DIRETTIVE:
${directives}

FUNZIONI SELEZIONATE:
${JSON.stringify(features, null, 2)}

RICHIESTA:
${prompt}

Restituisci direttamente i blocchi di codice e una breve spiegazione delle modifiche.
`;
  }

  if (type === "auto") {
    return `${rules}

Stai eseguendo UN SOLO ciclo di auto-evoluzione.

Analizza il codice e individua una nuova miglioria concreta.

La miglioria deve:
- essere utile
- essere compatibile con ciò che esiste
- non eliminare funzioni
- non riscrivere inutilmente il sito
- essere inseribile come patch
- usare lo stesso nome quando viene modificata una funzione

NON restituire l'intero index.html.

Restituisci soltanto la patch.

Usa questo formato:

=== REPLACE FUNCTION: nomeFunzione ===

[funzione migliorata]

=== END FUNCTION ===

oppure:

=== ADD ===

[nuovo codice]

=== END ADD ===

Puoi usare entrambi nello stesso risultato.

Alla fine indica brevemente:
- cosa hai aggiunto
- perché è utile
- eventuali dipendenze necessarie
- se è consigliabile continuare con un altro ciclo

CODICE ATTUALE:
${code}

DIRETTIVE:
${directives}

CICLO:
${body.round || 1}
`;
  }

  throw new Error("Tipo non supportato");
}

async function generateWithTimeout(model, prompt) {
  const timeout = new Promise((_, reject) => {
    setTimeout(() => {
      reject(new Error("Timeout generazione AI"));
    }, REQUEST_TIMEOUT);
  });

  const generation = model.generateContent(prompt);

  const result = await Promise.race([
    generation,
    timeout
  ]);

  return result.response.text();
}

function sanitizeAiText(text) {
  if (typeof text !== "string") {
    return "";
  }

  return text
    .replace(/\u0000/g, "")
    .trim();
}

function looksLikeAbuse(text) {
  const value = String(text || "").toLowerCase();

  const suspiciousPatterns = [
    /ignore previous instructions/,
    /ignore all previous instructions/,
    /system prompt/,
    /reveal your prompt/,
    /reveal hidden/,
    /api key/,
    /steal credentials/,
    /password dump/,
    /token dump/,
    /cookie theft/
  ];

  let matches = 0;

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(value)) {
      matches++;
    }
  }

  return matches >= 3;
}

export default async function handler(req, res) {
  const origin = getOrigin(req);
  const ip = getClientIp(req);

  res.setHeader("Vary", "Origin");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");

  if (allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "POST, OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  );

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return json(res, 405, {
      error: "Method not allowed"
    });
  }

  if (!allowedOrigins.has(origin)) {
    return json(res, 403, {
      error: "Origin non autorizzata"
    });
  }

  const requestSize = getRequestSize(req);

  if (requestSize > MAX_BODY_BYTES) {
    return json(res, 413, {
      error: "Richiesta troppo grande"
    });
  }

  const rate = checkRateLimit(ip);

  if (!rate.allowed) {
    res.setHeader(
      "Retry-After",
      String(rate.retryAfter)
    );

    return json(res, 429, {
      error: "Troppe richieste",
      retryAfter: rate.retryAfter
    });
  }

  const active = activeStore.get(ip) || 0;

  if (active >= 2) {
    return json(res, 429, {
      error: "Troppe generazioni contemporanee"
    });
  }

  activeStore.set(ip, active + 1);

  try {
    if (!process.env.GEMINI_API_KEY) {
      return json(res, 500, {
        error: "GEMINI_API_KEY non configurata sul server"
      });
    }

    let body = req.body;

    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch {
        return json(res, 400, {
          error: "JSON body non valido"
        });
      }
    }

    const validated = validateBody(body);

    const combinedText = [
      validated.idea,
      validated.code,
      validated.directives,
      validated.previousCode,
      validated.prompt,
      JSON.stringify(validated.features)
    ].join("\n");

    if (looksLikeAbuse(combinedText)) {
      return json(res, 400, {
        error: "Richiesta rifiutata"
      });
    }

    const genAI = new GoogleGenerativeAI(
      process.env.GEMINI_API_KEY
    );

    const modelName =
      process.env.GEMINI_MODEL ||
      "gemini-3.1-flash-lite";

    const temperature = Number(
      process.env.GEMINI_TEMPERATURE || 0.3
    );

    const maxOutputTokens = Number(
      process.env.GEMINI_MAX_OUTPUT_TOKENS || 12000
    );

    const model = genAI.getGenerativeModel({
      model: modelName,
      generationConfig: {
        temperature,
        maxOutputTokens
      }
    });

    const prompt = buildPrompt(validated);

    const text = sanitizeAiText(
      await generateWithTimeout(model, prompt)
    );

    if (!text) {
      return json(res, 502, {
        error: "Gemini ha restituito una risposta vuota"
      });
    }

    res.setHeader("Content-Type", "text/plain; charset=utf-8");

    return res.status(200).send(text);
  } catch (error) {
    console.error("AI Forge API error:", {
      ip,
      type: req.body?.type || null,
      mode: req.body?.mode || null,
      message: error?.message || "Errore sconosciuto"
    });

    return json(res, 500, {
      error: error?.message || "Errore interno del server"
    });
  } finally {
    const active = activeStore.get(ip) || 1;

    if (active <= 1) {
      activeStore.delete(ip);
    } else {
      activeStore.set(ip, active - 1);
    }
  }
}

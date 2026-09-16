import { GoogleGenAI } from "@google/genai";

const ALLOWED_ORIGINS = new Set([
  "https://www.alexs286.github.io",
  "https://alexs286.github.io"
]);

const ALLOWED_MODELS = new Set([
  "gemini-2.5-flash",
  "gemini-2.5-flash-lite",
  "gemini-3.1-flash-lite",
  "gemini-3.5-flash",
  "gemini-3.5-flash-lite",
  "gemini-3.6-flash",
  "gemini-3.7-flash",
  "gemini-3.8-flash"
]);

const DEFAULT_MODEL = "gemini-3.5-flash-lite";
const MAX_INPUT_CHARS = 900_000;
const MAX_ROUNDS = 8;

const COMMON_SYSTEM_RULES = `
Sei un senior software engineer specializzato in refactoring conservativo.

OBIETTIVO PRINCIPALE
Migliora il codice senza distruggerlo, senza trasformarlo in codice minificato e senza perdere funzionalità esistenti.

REGOLE ASSOLUTE
- NON eliminare funzioni, metodi, handler, event listener, route, endpoint, classi, componenti, elementi UI, API esistenti o flussi funzionanti.
- Mantieni esattamente i nomi delle funzioni e dei simboli pubblici già presenti.
- Mantieni gli ID, le classi CSS, i data-attribute, i nomi degli eventi, le route e i selettori usati dal codice esistente, salvo quando una sostituzione è indispensabile e viene resa compatibile.
- Mantieni la compatibilità con il codice già esistente.
- Non riscrivere inutilmente intere sezioni che non richiedono modifiche.
- Non sostituire una tecnologia, libreria o architettura funzionante solo per preferenza personale.
- Non aggiungere dipendenze esterne salvo necessità tecnica reale.
- NON minificare HTML, CSS o JavaScript.
- Mantieni una formattazione leggibile, con indentazione coerente e righe ragionevoli.
- CSS: mezzo compatto. Riduci spaziature inutili e ripetizioni evidenti, ma conserva selettori e regole leggibili. Niente CSS minificato.
- JavaScript/TypeScript/Python/PHP/Java/C#/Java/etc.: privilegia leggibilità e struttura, non compattezza artificiale.
- ZERO commenti nel codice finale. Elimina i commenti esistenti senza eliminare il codice a cui si riferiscono.
- Non inserire API key, password, token, cookie segreti o altre credenziali nel frontend.
- Se serve backend, crea o usa un endpoint separato e descrivi il contratto.
- Non inventare API, librerie, metodi o funzioni inesistenti.
- Non considerare “codice più corto” come criterio di qualità.
- Prima di modificare ragiona su dipendenze, flussi, stato, side effect e compatibilità.
- Dopo la modifica verifica mentalmente sintassi, riferimenti, chiamate, eventi, selettori, import/export e integrazioni.
- Se una modifica rischia di rompere compatibilità, scegli l'alternativa conservativa.
- Una funzione può essere rimossa solo se è chiaramente duplicata, irraggiungibile o inutile E se la richiesta esplicita lo consente. In questo sistema la rimozione non è consentita.
- Non sostituire una funzione esistente con una variante anonima o con una funzione rinominata.
- Quando una funzione esistente viene migliorata, mantieni esattamente lo stesso nome e lo stesso contratto esterno, salvo compatibilità retroattiva equivalente.
`;

function setCors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");
}

function fail(res, status, error, details = undefined) {
  const payload = { error };
  if (details !== undefined) payload.details = details;
  return res.status(status).json(payload);
}

function cleanString(value, max = MAX_INPUT_CHARS) {
  if (value == null) return "";
  return String(value).slice(0, max);
}

function cleanArray(value, limit = 50) {
  return Array.isArray(value) ? value.slice(0, limit) : [];
}

function cleanObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function normalizeModel(model) {
  const value = cleanString(model, 100).trim();
  return ALLOWED_MODELS.has(value) ? value : DEFAULT_MODEL;
}

function countApproximateCodeSize(code) {
  return Buffer.byteLength(code, "utf8");
}

function buildIssueSchema() {
  return {
    type: "object",
    properties: {
      issues: {
        type: "array",
        items: {
          type: "object",
          properties: {
            name: { type: "string" },
            level: { type: "string", enum: ["grave", "medio", "non-grave"] },
            detail: { type: "string" }
          },
          required: ["name", "level", "detail"]
        }
      },
      features: {
        type: "array",
        items: {
          type: "object",
          properties: {
            name: { type: "string" },
            detail: { type: "string" }
          },
          required: ["name", "detail"]
        }
      },
      summary: { type: "string" },
      preservedContracts: {
        type: "array",
        items: { type: "string" }
      }
    },
    required: ["issues", "features", "summary", "preservedContracts"]
  };
}

function buildImproveSchema() {
  return {
    type: "object",
    properties: {
      code: { type: "string" },
      summary: { type: "string" },
      apiNeeded: { type: "boolean" },
      apiNotes: { type: "string" },
      removedFunctions: {
        type: "array",
        items: { type: "string" }
      },
      renamedFunctions: {
        type: "array",
        items: { type: "string" }
      },
      changedPublicContracts: {
        type: "array",
        items: { type: "string" }
      },
      remainingSevereProblems: {
        type: "array",
        items: { type: "string" }
      },
      verification: {
        type: "object",
        properties: {
          syntaxReviewed: { type: "boolean" },
          compatibilityReviewed: { type: "boolean" },
          behaviorPreserved: { type: "boolean" },
          formattingPreserved: { type: "boolean" }
        },
        required: [
          "syntaxReviewed",
          "compatibilityReviewed",
          "behaviorPreserved",
          "formattingPreserved"
        ]
      }
    },
    required: [
      "code",
      "summary",
      "apiNeeded",
      "apiNotes",
      "removedFunctions",
      "renamedFunctions",
      "changedPublicContracts",
      "remainingSevereProblems",
      "verification"
    ]
  };
}

function buildAutoSchema() {
  return {
    type: "object",
    properties: {
      patch: {
        type: "object",
        properties: {
          functions: {
            type: "array",
            items: {
              type: "object",
              properties: {
                name: { type: "string" },
                code: { type: "string" }
              },
              required: ["name", "code"]
            }
          },
          insertions: {
            type: "array",
            items: {
              type: "object",
              properties: {
                marker: { type: "string" },
                code: { type: "string" },
                newline: { type: "boolean" }
              },
              required: ["marker", "code", "newline"]
            }
          }
        },
        required: ["functions", "insertions"]
      },
      summary: { type: "string" },
      continue: { type: "boolean" }
    },
    required: ["patch", "summary", "continue"]
  };
}

function buildAnalyzePrompt({ idea, code, directives, api, mode }) {
  return `${COMMON_SYSTEM_RULES}

MODALITÀ: ${mode}

Analizza il progetto senza modificarlo.

Devi produrre:
1. problemi GRAVI: possono rompere il progetto, impedire l'avvio, causare errori runtime importanti, rompere integrazioni o perdere funzionalità;
2. problemi MEDI: rompono o degradano una singola funzione o una parte specifica;
3. problemi NON-GRAVI: qualità, ridondanze, warning, piccoli rischi o codice superfluo.

Proponi da 5 a 12 miglioramenti concretamente applicabili, ma NON proporre la rimozione di funzionalità.

Per ogni elemento sii concreto e tecnico. Evita suggerimenti generici come “migliorare il codice”.

Idea:
${idea}

Direttive dell'utente:
${directives}

Informazioni API:
${api}

Codice:
<<<CODE>>>
${code}
<<<END CODE>>>

Elenca anche i contratti che devono essere preservati: funzioni, eventi, ID, classi, route, API, componenti, output e comportamenti osservabili importanti.`;
}

function buildImprovePrompt({
  idea,
  code,
  directives,
  api,
  issues,
  features,
  previousCode,
  round,
  constraints,
  prompt
}) {
  const source = previousCode || code;

  return `${COMMON_SYSTEM_RULES}

ESEGUI UN CICLO DI MIGLIORAMENTO CONSERVATIVO.
Round: ${round}

FASE 1 — INVENTARIO DI CONSERVAZIONE
Prima di modificare, individua mentalmente:
- tutte le funzioni e i metodi esistenti;
- handler e listener;
- ID/classi/data-attribute usati dal comportamento;
- API, route, endpoint e contratti esterni;
- componenti e sezioni UI;
- import/export e dipendenze;
- flussi e comportamenti già funzionanti.

FASE 2 — MODIFICA
- Risolvi i problemi selezionati.
- Applica i miglioramenti selezionati.
- Mantieni tutte le funzionalità esistenti.
- Mantieni i nomi delle funzioni esistenti.
- Non riscrivere parti sane senza motivo tecnico.
- NON minificare.
- Mantieni il codice leggibile.
- CSS mezzo compatto, non minificato.
- ZERO commenti nel codice finale.
- Non introdurre librerie o API non necessarie.

FASE 3 — VERIFICA
Prima di restituire il risultato controlla:
- nessuna funzione rimossa;
- nessuna funzione rinominata;
- nessun contratto pubblico rotto;
- nessun handler scollegato;
- nessun ID/class/data-attribute necessario eliminato;
- nessun import/export incoerente;
- nessuna route o endpoint cambiato senza compatibilità;
- sintassi plausibilmente valida;
- miglioramenti effettivamente applicati;
- formattazione leggibile;
- commenti assenti.

REGOLA CRITICA
Se per applicare un miglioramento devi sacrificare una funzionalità esistente, NON applicare quella parte del miglioramento. Preferisci una soluzione compatibile.

Idea:
${idea}

Direttive dell'utente:
${directives}

Informazioni API:
${api}

Problemi selezionati:
${JSON.stringify(cleanArray(issues), null, 2)}

Funzioni e miglioramenti selezionati:
${JSON.stringify(cleanArray(features), null, 2)}

Vincoli:
${JSON.stringify(cleanObject(constraints), null, 2)}

Istruzioni aggiuntive:
${prompt}

CODICE ATTUALE:
<<<CODE>>>
${source}
<<<END CODE>>>

Restituisci il codice completo aggiornato, non una patch parziale.`;
}

function buildAutoPrompt({ code, round, directives }) {
  return `${COMMON_SYSTEM_RULES}

Esegui un singolo passaggio di auto-miglioramento NON distruttivo.
Round: ${round}

Scegli una sola miglioria concreta con rischio basso.
Non rimuovere o rinominare funzioni.
Non alterare API pubbliche o comportamenti esistenti.
Non minificare.
Mantieni il CSS mezzo compatto.
ZERO commenti nel codice prodotto.

Direttive:
${directives}

Codice attuale:
<<<CODE>>>
${code}
<<<END CODE>>>

Restituisci solo una patch applicabile composta da modifiche mirate a funzioni esistenti e/o inserimenti in marker sicuri.`;
}

async function generateJSON(ai, { model, prompt, schema, temperature }) {
  const response = await ai.models.generateContent({
    model,
    contents: prompt,
    config: {
      responseMimeType: "application/json",
      responseSchema: schema,
      ...(typeof temperature === "number" ? { temperature } : {})
    }
  });

  const text = String(response.text || "").trim();
  if (!text) throw new Error("Gemini ha restituito una risposta vuota");

  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`Risposta JSON non valida: ${error.message}`);
  }
}

function severeIssues(issues) {
  return cleanArray(issues).filter(item => {
    const level = String(item?.level || item?.severity || "").toLowerCase();
    return level === "grave" || (level.includes("grave") && !level.includes("non"));
  });
}

function validateImproveResult(result, previousCode) {
  if (!result || typeof result.code !== "string" || !result.code.trim()) {
    throw new Error("Il risultato non contiene codice valido");
  }

  if (!Array.isArray(result.removedFunctions)) result.removedFunctions = [];
  if (!Array.isArray(result.renamedFunctions)) result.renamedFunctions = [];
  if (!Array.isArray(result.changedPublicContracts)) result.changedPublicContracts = [];

  if (result.removedFunctions.length || result.renamedFunctions.length) {
    throw new Error(
      `Modifica non accettata: sono state rimosse/rinominate funzioni. Rimosse: ${result.removedFunctions.join(", ") || "nessuna"}; rinominate: ${result.renamedFunctions.join(", ") || "nessuna"}`
    );
  }

  const oldSize = countApproximateCodeSize(previousCode || "");
  const newSize = countApproximateCodeSize(result.code);

  if (oldSize > 2000 && newSize < oldSize * 0.45) {
    throw new Error("Modifica non accettata: il codice è diventato anormalmente più corto. Probabile perdita di funzionalità.");
  }

  return result;
}

export default async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return fail(res, 405, "Method not allowed");

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return fail(res, 500, "GEMINI_API_KEY non configurata sul server");

  try {
    const body = cleanObject(req.body);
    const type = cleanString(body.type || "analyze", 30).toLowerCase();
    const model = normalizeModel(body.model);

    const code = cleanString(body.code);
    const previousCode = cleanString(body.previousCode);
    const idea = cleanString(body.idea, 30_000);
    const directives = cleanString(body.directives, 50_000);
    const api = cleanString(body.api, 50_000);
    const prompt = cleanString(body.prompt, 50_000);
    const mode = cleanString(body.mode || "fix-and-improve", 100);
    const round = Math.min(Math.max(Number(body.round) || 1, 1), MAX_ROUNDS);
    const issues = cleanArray(body.issues);
    const features = cleanArray(body.features);
    const constraints = cleanObject(body.constraints);

    if (!code && !previousCode && type !== "analyze") {
      return fail(res, 400, "Codice mancante");
    }

    const ai = new GoogleGenAI({ apiKey });

    if (type === "analyze") {
      const data = await generateJSON(ai, {
        model,
        prompt: buildAnalyzePrompt({ idea, code, directives, api, mode }),
        schema: buildIssueSchema(),
        temperature: 0.15
      });

      data.issues = cleanArray(data.issues, 100);
      data.features = cleanArray(data.features, 20);
      data.preservedContracts = cleanArray(data.preservedContracts, 200);
      return res.status(200).json(data);
    }

    if (type === "generate" || type === "regenerate") {
      const source = previousCode || code;
      const promptText = buildImprovePrompt({
        idea,
        code,
        directives,
        api,
        issues,
        features,
        previousCode: source,
        round,
        constraints,
        prompt
      });

      let data;
      try {
        data = await generateJSON(ai, {
          model,
          prompt: promptText,
          schema: buildImproveSchema()
        });
        data = validateImproveResult(data, source);
      } catch (firstError) {
        const recoveryPrompt = `${promptText}\n\nRECOVERY OBBLIGATORIA:\nLa prima generazione è stata rifiutata perché ha violato un vincolo di conservazione. Rigenera una versione più conservativa. Non rimuovere o rinominare nessuna funzione. Non accorciare artificialmente il codice. Mantieni tutte le funzionalità. Produci il codice completo.`;
        data = await generateJSON(ai, {
          model,
          prompt: recoveryPrompt,
          schema: buildImproveSchema()
        });
        try {
          data = validateImproveResult(data, source);
        } catch {
          throw firstError;
        }
      }

      data.removedFunctions = cleanArray(data.removedFunctions, 100);
      data.renamedFunctions = cleanArray(data.renamedFunctions, 100);
      data.changedPublicContracts = cleanArray(data.changedPublicContracts, 100);
      data.remainingSevereProblems = cleanArray(data.remainingSevereProblems, 100);
      return res.status(200).json(data);
    }

    if (type === "auto") {
      const data = await generateJSON(ai, {
        model,
        prompt: buildAutoPrompt({ code, round, directives }),
        schema: buildAutoSchema(),
        temperature: 0.2
      });
      return res.status(200).json(data);
    }

    return fail(res, 400, "Tipo di richiesta non valido");
  } catch (error) {
    console.error("CodeForge API error", error);
    return fail(res, 502, "Errore durante l'elaborazione del codice", error?.message || "Errore sconosciuto");
  }
}

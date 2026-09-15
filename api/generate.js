import { GoogleGenerativeAI } from "@google/generative-ai";

export default async function handler(req, res) {
  const allowedOrigins = ["https://www.alexs286.github.io", "https://alexs286.github.io"];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({error: "Method not allowed"});
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({error: "GEMINI_API_KEY non configurata sul server"});
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({
      model: "gemini-3.1-flash-lite",
      generationConfig: {responseMimeType: "application/json", temperature: 0.2, maxOutputTokens: 15000}
    });
    const body = req.body || {};
    const { type, code, req: userReq, issues } = body;
    let schema = "";
    let task = "";
    const guard = `Regole obbligatorie: NON rimuovere o alterare funzioni non correlate ai problemi. Restituisci SEMPRE il codice intero, non troncarlo mai, gestisci i testi lunghi. Zero commenti nel codice generato. Se modifichi una funzione, mantieni lo stesso nome.`;
    if(type === "analyze"){
      task = `Analizza il codice fornito e trova vulnerabilità, errori o inefficienze. Classificali in red (gravi), yellow (funzionalità specifiche), green (minori). ${guard}\nCodice:\n${code}\nRichieste utente:\n${userReq}`;
      schema = `{"issues":[{"id":"i1","title":"Nome Problema","desc":"Descrizione","severity":"red|yellow|green","status":"pending"}]}`;
    } else if(type === "fix"){
      task = `Correggi il codice seguente basandoti sui problemi elencati. Restituisci il codice completo corretto e aggiorna lo stato dei problemi (resolved, failed, gone). ${guard}\nCodice attuale:\n${code}\nProblemi:\n${JSON.stringify(issues)}`;
      schema = `{"code":"codice completo senza commenti","issues":[{"id":"i1","title":"...","desc":"...","severity":"red|yellow|green","status":"resolved|failed|gone"}]}`;
    } else if(type === "verify"){
      task = `Controlla il codice per verificare se i problemi precedenti sono effettivamente risolti. Aggiorna gli status. Se necessita ulteriori fix minori, aggiorna il codice, altrimenti restituiscilo identico. ${guard}\nCodice:\n${code}\nProblemi:\n${JSON.stringify(issues)}`;
      schema = `{"code":"codice completo senza commenti","issues":[{"id":"i1","title":"...","desc":"...","severity":"red|yellow|green","status":"resolved|failed|gone"}]}`;
    } else {
      return res.status(400).json({error: "Tipo non valido"});
    }
    const result = await model.generateContent(`${task}\nRispondi con UN SOLO oggetto JSON valido corrispondente a:\n${schema}`);
    let text = result.response.text().replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
    let json;
    try {
      json = JSON.parse(text);
    } catch(e) {
      return res.status(502).json({error: "Risposta AI non valida", details: text});
    }
    return res.status(200).json(json);
  } catch(error) {
    return res.status(500).json({error: error.message || "Errore interno"});
  }
}

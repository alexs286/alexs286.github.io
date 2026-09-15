import { GoogleGenerativeAI } from "@google/generative-ai";

export default async function handler(req, res) {
  const allowedOrigins = ["https://www.alexs286.github.io","https://alexs286.github.io"];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({error:"Method not allowed"});
  
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({error:"GEMINI_API_KEY non configurata"});

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const { type, idea, code, request, features } = req.body || {};
    
    let modelConfig = { model: "gemini-3.1-flash-lite", generationConfig: { temperature: 0.2, maxOutputTokens: 8000 } };
    let task = "";

    const guard = `Regole: CSS compatto, ZERO commenti. NON REsTITUIRE MAI L'INTERO CODICE.`;

    if (type === "analyze") {
      modelConfig.generationConfig.responseMimeType = "application/json";
      task = `Analizza il codice/idea. Restituisci JSON: {"features":[{"id":"f1","name":"Nome","desc":"Dettaglio"}]} ${guard}\nIdea: ${idea}\nRichiesta: ${request}\nCodice esistente:\n${code}`;
    } else if (type === "verify") {
      modelConfig.generationConfig.responseMimeType = "application/json";
      task = `Controlla questo codice e dimmi quali di queste funzioni sono EFFETTIVAMENTE implementate e funzionanti al suo interno.
Codice:\n${code}\n
Funzioni da cercare: ${JSON.stringify(features)}
Restituisci SOLO un array JSON di ID delle funzioni trovate, es: ["f1", "f3"]`;
    } else if (type === "patch") {
      task = `Genera SOLO il codice per aggiungere/modificare queste funzioni: ${JSON.stringify(features)}
Richiesta utente: ${request}
Codice attuale:\n${code}
${guard}
Usa ESATTAMENTE questo formato Markdown testuale, NON JSON:

Per SOSTITUIRE o CREARE una funzione JS:
[REPLACE_FUNC: nomeFunzione]
\`\`\`javascript
function nomeFunzione() { ... }
\`\`\`

Per AGGIUNGERE qualcosa in fondo al body:
[INSERT_BODY]
\`\`\`html
<script>...</script>
\`\`\`

Per AGGIUNGERE qualcosa nell'head:
[INSERT_HEAD]
\`\`\`html
<style>...</style>
\`\`\`
`;
    } else {
      return res.status(400).json({error:"Invalid type"});
    }

    const model = genAI.getGenerativeModel(modelConfig);
    const result = await model.generateContent(task);
    const text = result.response.text();

    if (type === "analyze" || type === "verify") {
      let json;
      try { 
        json = JSON.parse(text.replace(/^```(?:json)?/i,"").replace(/```$/,"").trim());
      } catch { 
        const match = text.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
        json = match ? JSON.parse(match[0]) : (type === "verify" ? [] : {features:[]});
      }
      return res.status(200).json(json);
    }

    return res.status(200).json({ rawText: text });

  } catch(error) {
    return res.status(500).json({error:error.message});
  }
}

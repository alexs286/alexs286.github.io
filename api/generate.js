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
  if (!apiKey) return res.status(500).json({error:"GEMINI_API_KEY non configurata sul server"});
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({
      model:"gemini-3.1-flash-lite",
      generationConfig:{responseMimeType:"application/json",temperature:0.3,maxOutputTokens:12000}
    });
    const body=req.body||{};
    const {type,mode,idea,code,directives,features,previousCode,round,constraints,prompt}=body;
    let schema="";
    let task="";
    const guard=`Regole obbligatorie:
- Il risultato del sito deve essere un UNICO file index.html con HTML, CSS e JS nello stesso file.
- CSS mezzo compatto: leggibile ma non spezzato inutilmente.
- ZERO commenti nel codice.
- Non rimuovere né sostituire funzioni esistenti solo per aggiungerne altre.
- Preferisci aggiunte locali e modulari, con funzioni JavaScript nominate.
- Quando devi migliorare una funzione esistente, restituisci la funzione migliorata con lo stesso identico nome.
- Mantieni compatibilità con ciò che esiste già.
- Evita dipendenze esterne salvo necessità reale.
- Se una funzione frontend richiede server-side, descrivi un endpoint API separato nella risposta, senza incorporare segreti nel client.`;
    if(type==="analyze"){
      task=`Analizza il progetto senza generare ancora il sito. Fornisci tra 5 e 12 funzioni o dettagli che l'utente può selezionare. ${guard}
Modalità: ${mode}
Idea: ${idea||""}
Codice esistente: ${code||""}
Direttive: ${directives||""}`;
      schema=`{"features":[{"name":"Nome funzione","detail":"Dettaglio concreto"}],"summary":"Sintesi"}`
    } else if(type==="generate"||type==="regenerate"){
      task=`Genera o rigenera il sito. ${guard}
Modalità: ${mode}
Idea originale: ${idea||""}
Direttive: ${directives||""}
Funzioni selezionate: ${JSON.stringify(features||[])}
Codice precedente: ${previousCode||code||""}
Vincoli tecnici: ${JSON.stringify(constraints||{})}
Restituisci il codice completo index.html aggiornato.`;
      schema=`{"code":"<!doctype html>...","summary":"Cosa è stato aggiunto o migliorato","apiNeeded":false,"apiNotes":""}`
    } else if(type==="auto"){
      task=`Esegui un solo passaggio di auto-evoluzione incrementale. ${guard}
Codice attuale:
${code||""}
Trova una sola miglioria utile, non distruttiva. Preferisci un'aggiunta che possa essere inserita senza riscrivere tutto. Per funzioni migliorate usa il nome funzione come chiave di sostituzione.
Passaggio: ${round||1}`;
      schema=`{"patch":{"functions":[{"name":"nomeFunzione","code":"function nomeFunzione(){...}"}],"insertions":[{"marker":"</body>","code":"<script>...</script>","newline":true}]},"summary":"Miglioria","continue":true}`
    } else {
      return res.status(400).json({error:"Tipo di richiesta non valido"});
    }
    const result=await model.generateContent(`${task}
${prompt||""}
Rispondi con UN SOLO oggetto JSON valido, senza markdown, seguendo esattamente questa struttura:
${schema}`);
    let text=result.response.text().replace(/^```(?:json)?/i,"").replace(/```$/,"").trim();
    let json;
    try{json=JSON.parse(text)}catch{return res.status(502).json({error:"Gemini ha restituito un JSON non valido",details:text})}
    return res.status(200).json(json);
  } catch(error) {
    return res.status(500).json({error:error.message||"Errore interno del server"});
  }
}

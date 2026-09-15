import { GoogleGenerativeAI } from "@google/generative-ai";

export default async function handler(req,res){
const allowedOrigins=["https://www.alexs286.github.io","https://alexs286.github.io"];
const origin=req.headers.origin;
if(allowedOrigins.includes(origin))res.setHeader("Access-Control-Allow-Origin",origin);
res.setHeader("Vary","Origin");
res.setHeader("Access-Control-Allow-Methods","POST, OPTIONS");
res.setHeader("Access-Control-Allow-Headers","Content-Type");
if(req.method==="OPTIONS")return res.status(204).end();
if(req.method!=="POST")return res.status(405).json({error:"Method not allowed"});
const apiKey=process.env.GEMINI_API_KEY;
if(!apiKey)return res.status(500).json({error:"GEMINI_API_KEY non configurata sul server"});

try{
const body=req.body||{};
const modelName=body.model||"gemini-3.1-flash-lite";
const genAI=new GoogleGenerativeAI(apiKey);
const model=genAI.getGenerativeModel({
model:modelName,
generationConfig:{responseMimeType:"application/json",temperature:.2,maxOutputTokens:12000}
});

const {type,mode,idea,code,directives,problems,previousCode,constraints,chunkIndex,totalChunks,prompt}=body;

const guard=`Regole obbligatorie:
- CSS mezzo compatto
- ZERO commenti
- Non eliminare funzioni esistenti senza una ragione tecnica indispensabile
- Non sostituire una funzione esistente con una funzione diversa
- Mantieni tutti i comportamenti e le funzionalità già presenti
- Quando modifichi una funzione mantieni esattamente lo stesso nome
- Non rimuovere event listener, elementi DOM, API, variabili o dipendenze funzionanti
- Preferisci correzioni minime e conservative
- Non introdurre dipendenze esterne se non indispensabili
- Non inserire API key o segreti nel codice frontend
- Se una funzione richiede server-side, segnala apiNeeded e apiNotes
- Il codice restituito deve essere completo e direttamente utilizzabile`;

let task="";
let schema="";

if(type==="analyze"){
task=`Analizza il codice esclusivamente per trovare problemi reali.
Non riscrivere il codice.
Individua problemi gravi che possono rompere il sito o funzionalità fondamentali, problemi medi che compromettono singole funzioni senza rompere tutto e problemi bassi che non rompono codice o funzioni ma rappresentano difetti o miglioramenti tecnici.
Restituisci da 1 a 20 problemi concreti.
Ogni problema deve avere title,detail,severity.
severity deve essere esclusivamente high,medium oppure low.
Se il codice è un chunk ${chunkIndex+1||1} di ${totalChunks||1}, considera solo ciò che puoi dimostrare dal chunk.
${guard}
Modalità:${mode||"diagnostic"}
Richiesta:${idea||""}
Codice:
${code||""}`;
schema=`{"issues":[{"title":"Problema","detail":"Spiegazione","severity":"high"}],"summary":"Sintesi"}`;

}else if(type==="apply"){
task=`Correggi il codice usando esclusivamente i problemi forniti.
Devi preservare tutte le funzioni già presenti.
Non riscrivere parti non necessarie.
Non eliminare funzionalità per risolvere problemi.
Prima confronta mentalmente codice precedente e codice corretto e assicurati che le funzioni esistenti siano ancora presenti.
Restituisci il codice completo.
${guard}
Problemi:
${JSON.stringify(problems||[])}
Codice precedente:
${previousCode||code||""}
Codice da correggere:
${code||""}
Richiesta:
${directives||idea||""}`;
schema=`{"code":"<!doctype html>","summary":"Modifiche effettuate","apiNeeded":false,"apiNotes":"","preservedFunctions":[]}`;

}else if(type==="verify"){
task=`Verifica il codice aggiornato rispetto ai problemi precedentemente rilevati.
Per ogni problema indica se è stato risolto.
resolved deve essere true se è stato risolto, false se persiste.
fixed può essere usato come sinonimo di resolved.
Se un problema non esiste più ma non puoi dimostrare con certezza che sia stato risolto, usa severity low e descrivilo.
Non modificare il codice.
${guard}
Problemi precedenti:
${JSON.stringify(problems||[])}
Codice aggiornato:
${code||""}`;
schema=`{"results":[{"title":"Problema","detail":"Risultato verifica","severity":"low","resolved":true}],"summary":"Sintesi verifica"}`;

}else{
return res.status(400).json({error:"Tipo di richiesta non valido"});
}

const result=await model.generateContent(`${task}
${prompt||""}

Rispondi con UN SOLO oggetto JSON.
Non usare markdown.
Non usare blocchi.
Rispetta esattamente la struttura:
${schema}`);

const text=result.response.text().trim();

let json;
try{
json=JSON.parse(text);
}catch{
return res.status(502).json({
error:"Gemini ha restituito un JSON non valido",
details:text,
model:modelName
});
}

return res.status(200).json(json);

}catch(error){
return res.status(500).json({error:error.message||"Errore interno del server"});
}
}

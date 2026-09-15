import { GoogleGenerativeAI } from "@google/generative-ai";

export default async function handler(req,res){
const allowedOrigins=["https://www.alexs286.github.io","https://alexs286.github.io"];
const origin=req.headers.origin;
if(allowedOrigins.includes(origin))res.setHeader("Access-Control-Allow-Origin",origin);
res.setHeader("Vary","Origin");
res.setHeader("Access-Control-Allow-Methods","POST,OPTIONS");
res.setHeader("Access-Control-Allow-Headers","Content-Type");
if(req.method==="OPTIONS")return res.status(204).end();
if(req.method!=="POST")return res.status(405).json({error:"Method not allowed"});

const apiKey=process.env.GEMINI_API_KEY;
if(!apiKey)return res.status(500).json({error:"GEMINI_API_KEY non configurata sul server"});

try{
const body=req.body||{};
const {
type="analyze",
mode="fix-and-improve",
idea="",
code="",
directives="",
api="",
features=[],
issues=[],
previousCode="",
round=1,
constraints={},
prompt="",
model="gemini-3.1-flash-lite"
}=body;

const genAI=new GoogleGenerativeAI(apiKey);
const selectedModel=model||"gemini-3.1-flash-lite";

const guard=`Regole obbligatorie:
- CSS mezzo compatto.
- ZERO commenti nel codice.
- Quando migliori una funzione esistente mantieni esattamente lo stesso nome.
- Mantieni compatibilità con il codice già esistente.
- Non eliminare funzionalità funzionanti senza una ragione tecnica.
- Non aggiungere dipendenze esterne se non sono realmente necessarie.
- Non inserire chiavi API, password, token o segreti nel frontend.
- Se una funzionalità richiede server-side, restituisci una soluzione compatibile con un endpoint separato.
- Restituisci codice completo quando viene richiesto.
- Non usare markdown nel JSON.
- Non inventare API inesistenti.
- Individua anche problemi introdotti durante un precedente miglioramento.`;

let task="";
let schema="";

if(type==="analyze"){
task=`Analizza rigorosamente il progetto senza modificarlo.

Devi individuare:
1. problemi GRAVI: errori che possono rompere il progetto, impedire l'avvio, rompere parti importanti o creare malfunzionamenti strutturali;
2. problemi MEDI: problemi che rompono una singola funzione, comportamento o parte specifica;
3. problemi NON-GRAVI: warning, codice morto, ridondanze, qualità, piccole inefficienze o codice spazzatura.

Devi inoltre proporre da 5 a 12 funzioni, miglioramenti o suggerimenti concretamente applicabili.

${guard}

Modalità:
${mode}

Idea:
${idea}

Codice:
${code}

Direttive:
${directives}

Informazioni API:
${api}`;

schema=`{
"issues":[
{"name":"Nome","level":"grave","detail":"Descrizione tecnica precisa"},
{"name":"Nome","level":"medio","detail":"Descrizione tecnica precisa"},
{"name":"Nome","level":"non-grave","detail":"Descrizione tecnica precisa"}
],
"features":[
{"name":"Nome funzione","detail":"Descrizione concreta"}
],
"summary":"Sintesi tecnica"
}`;

}else if(type==="generate"||type==="regenerate"){
task=`Genera il codice completo aggiornato.

Devi eseguire questo processo:
1. analizza il codice;
2. risolvi i problemi selezionati;
3. migliora il codice;
4. aggiungi le funzioni selezionate;
5. controlla che il risultato non introduca problemi;
6. restituisci l'intero codice aggiornato.

${guard}

Idea:
${idea}

Direttive:
${directives}

Informazioni API:
${api}

Problemi selezionati:
${JSON.stringify(issues)}

Funzioni e suggerimenti selezionati:
${JSON.stringify(features)}

Codice precedente:
${previousCode||code}

Round:
${round}

Vincoli:
${JSON.stringify(constraints)}

Istruzioni aggiuntive:
${prompt}`;

schema=`{
"code":"<!doctype html>...",
"summary":"Descrizione delle modifiche",
"apiNeeded":false,
"apiNotes":"",
"remainingSevereProblems":[]
}`;

}else if(type==="auto"){
task=`Esegui un singolo passaggio di auto-evoluzione.

Analizza il codice attuale, trova una miglioria utile e non distruttiva, applicala e restituisci il risultato secondo la struttura richiesta.

${guard}

Codice:
${code}

Round:
${round}

Direttive:
${directives}`;

schema=`{
"patch":{
"functions":[{"name":"nomeFunzione","code":"function nomeFunzione(){}"}],
"insertions":[{"marker":"</body>","code":"<script></script>","newline":true}]
},
"summary":"Miglioria",
"continue":true
}`;

}else{
return res.status(400).json({error:"Tipo di richiesta non valido"});
}

const generationConfig={
responseMimeType:"application/json",
temperature:type==="analyze"?0.2:0.3,
maxOutputTokens:30000
};

const modelInstance=genAI.getGenerativeModel({
model:selectedModel,
generationConfig
});

const finalPrompt=`${task}

${prompt}

Rispondi con UN SOLO oggetto JSON valido.
Non aggiungere testo prima o dopo il JSON.
Segui esattamente questa struttura:

${schema}`;

const result=await modelInstance.generateContent(finalPrompt);
let text=result.response.text().trim();

text=text.replace(/^```json\s*/i,"").replace(/^```\s*/i,"").replace(/\s*```$/,"").trim();

let json;

try{
json=JSON.parse(text);
}catch(error){
return res.status(502).json({
error:"Gemini ha restituito un JSON non valido",
details:text,
parseError:error.message
});
}

return res.status(200).json(json);

}catch(error){
return res.status(500).json({
error:error.message||"Errore interno del server"
});
}
}

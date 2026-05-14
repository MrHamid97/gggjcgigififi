

const AUTH_KEY = "HRs1997";
const DEFAULT_AUTH_KEY = "CHANGE_ME_TO_A_STRONG_SECRET";
const RELAY_HOP_HEADER = "x-relay-hop";
const MAX_BATCH_SIZE = 40;
const SKIP_HEADERS = new Set([
 "host",
 "connection",
 "content-length",
 "transfer-encoding",
 "proxy-connection",
 "proxy-authorization",
 "priority",
 "te",
]);

export default {
 async fetch(request) {
  if (AUTH_KEY === DEFAULT_AUTH_KEY) {
   return json({ e: "configure AUTH_KEY in worker.js" }, 500);
  }

  if (request.method !== "POST") {
   return json({ e: "method not allowed" }, 405);
  }

  if (request.headers.get(RELAY_HOP_HEADER) === "1") {
   return json({ e: "loop detected" }, 508);
  }

  let req;
  try {
   req = await request.json();
  } catch (_err) {
   return json({ e: "bad json" }, 400);
  }

  if (!req || req.k !== AUTH_KEY) {
   return json({ e: "unauthorized" }, 401);
  }

  const selfHost = new URL(request.url).hostname;

  if (Array.isArray(req.q)) {
   if (req.q.length === 0) return json({ q: [] });
   if (req.q.length > MAX_BATCH_SIZE) {
    return json({
     e: "batch too large (" + req.q.length + " > " + MAX_BATCH_SIZE + ")",
    }, 400);
   }
   const results = await Promise.all(
    req.q.map((item) => processOne(item, selfHost).catch((err) => ({
     e: "fetch failed: " + String(err),
    })))
   );
   return json({ q: results });
  }


  let result;
  try {
   result = await processOne(req, selfHost);
  } catch (err) {
   return json({ e: "fetch failed: " + String(err) }, 502);
  }
  if (result.e) {

   return json(result, 400);
  }
  return json(result);
 },
};

async function processOne(item, selfHost) {
 if (!item || typeof item !== "object") {
  return { e: "bad item" };
 }
 if (!item.u || typeof item.u !== "string" || !/^https?:\/\//i.test(item.u)) {
  return { e: "bad url" };
 }

 let targetUrl;
 try {
  targetUrl = new URL(item.u);
 } catch (_err) {
  return { e: "bad url" };
 }
 if (targetUrl.hostname === selfHost) {
  return { e: "self-fetch blocked" };
 }

 const headers = new Headers();
 if (item.h && typeof item.h === "object") {
  for (const [k, v] of Object.entries(item.h)) {
   if (SKIP_HEADERS.has(k.toLowerCase())) continue;
   try {
    headers.set(k, v);
   } catch (_err) {
   }
  }
 }
 headers.set(RELAY_HOP_HEADER, "1");

 const method = (item.m || "GET").toUpperCase();
 const fetchOptions = {
  method,
  headers,
  redirect: item.r === false ? "manual" : "follow",
 };


 const bodyAllowed = method !== "GET" && method !== "HEAD";
 if (item.b && bodyAllowed) {
  try {
   const binary = Uint8Array.from(atob(item.b), (c) => c.charCodeAt(0));
   fetchOptions.body = binary;
   if (item.ct && !headers.has("content-type")) {
    headers.set("content-type", item.ct);
   }
  } catch (_err) {
   return { e: "bad body base64" };
  }
 }

 let resp;
 try {
  resp = await fetch(targetUrl.toString(), fetchOptions);
 } catch (err) {
  return { e: "fetch failed: " + String(err) };
 }

 const buffer = await resp.arrayBuffer();
 const uint8 = new Uint8Array(buffer);


 let binary = "";
 const chunkSize = 0x8000;
 for (let i = 0; i < uint8.length; i += chunkSize) {
  binary += String.fromCharCode.apply(null, uint8.subarray(i, i + chunkSize));
 }
 const base64 = btoa(binary);

 const responseHeaders = {};
 resp.headers.forEach((v, k) => {
  responseHeaders[k] = v;
 });

 return {
  s: resp.status,
  h: responseHeaders,
  b: base64,
 };
}

function json(obj, status = 200) {
 return new Response(JSON.stringify(obj), {
  status,
  headers: { "content-type": "application/json" },
 });
}

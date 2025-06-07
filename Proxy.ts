import { serve } from "https://deno.land/std@0.223.0/http/server.ts";
import * as protobuf from "https://esm.sh/protobufjs@7.4.0";

// Transform function mimicking bundle.js's r()
function transformR(input: string): string {
  return input.split("").map(char => {
    const code = char.charCodeAt(0);
    if (code >= 33 && code <= 126) {
      const shifted = 33 + ((code - 33 + 94) % 94); // Rotate within 33–126
      return String.fromCharCode(shifted);
    }
    return char;
  }).join("");
}

// Decrypt AES-CTR with What header as key and STOPSTOPSTOPSTOP as IV
async function decryptAES(encrypted: Uint8Array, whatHeader: string): Promise<string> {
  try {
    const key = new TextEncoder().encode(whatHeader);
    const iv = new TextEncoder().encode("STOPSTOPSTOPSTOP");
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-CTR" },
      false,
      ["decrypt"]
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CTR", counter: iv, length: 128 },
      cryptoKey,
      encrypted
    );
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error(`Decryption error: ${error.message}`);
    throw error;
  }
}

// Protobuf schema (inferred from bundle.js)
const protoSchema = `
syntax = "proto3";
message StreamResponse {
  string u = 1;
}
`;

// Deserialization with Protobuf and custom fallback
function deserializeBinary(data: string): string {
  console.log(`Deserializing input: ${data.slice(0, 50)}...`);
  try {
    // Try base64 decoding
    const bytes = new Uint8Array([...atob(data)].map(c => c.charCodeAt(0)));
    console.log(`Base64 decoded bytes: ${bytes.slice(0, 20)}...`);
    try {
      // Try Protobuf parsing
      const root = protobuf.parse(protoSchema);
      const StreamResponse = root.lookupType("StreamResponse");
      const message = StreamResponse.decode(bytes);
      const decoded = message.u || new TextDecoder().decode(bytes);
      console.log(`Protobuf decoded: ${decoded.slice(0, 50)}...`);
      return decoded;
    } catch (e) {
      console.log(`Protobuf failed: ${e.message}`);
      // Fallback: Use decoded bytes as string
      const decoded = new TextDecoder().decode(bytes);
      console.log(`Binary decoded: ${decoded.slice(0, 50)}...`);
      return decoded;
    }
  } catch {
    console.log(`Base64 failed`);
    try {
      // Custom fallback: Assume raw binary string
      const bytes = new Uint8Array(data.split("").map(c => c.charCodeAt(0)));
      const decoded = new TextDecoder().decode(bytes);
      console.log(`Raw binary decoded: ${decoded.slice(0, 50)}...`);
      // Heuristic: Extract string after first null byte (mimic getU())
      const nullIndex = decoded.indexOf("\0");
      const extracted = nullIndex >= 0 ? decoded.slice(nullIndex + 1) : decoded;
      console.log(`Extracted string: ${extracted.slice(0, 50)}...`);
      return extracted;
    } catch {
      console.log(`Raw binary failed, using raw: ${data.slice(0, 50)}...`);
      return data;
    }
  }
}

// Validate URL path
function sanitizePath(path: string): string {
  // Ensure path starts with / and contains only valid URL characters
  const sanitized = `/${path.replace(/^\/+/, "").replace(/[^a-zA-Z0-9\/._-]/g, "")}`;
  console.log(`Sanitized path: ${sanitized}`);
  // Check if path resembles a valid m3u8 path
  if (!sanitized.match(/^\/secure\/[a-zA-Z0-9]+\/[a-z]+\/stream\/[a-z-]+\/[0-9]+\/playlist\.m3u8$/)) {
    console.error(`Invalid m3u8 path format: ${sanitized}`);
    throw new Error(`Invalid m3u8 path: ${sanitized}`);
  }
  return sanitized;
}

serve(async (req: Request) => {
  if (req.method !== "POST" && req.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const headers = new Headers({
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
    "Accept": "application/vnd.apple.mpegurl, */*",
    "Origin": "https://embedstreams.top",
    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
    "Sec-Ch-Ua": "\"Chromium\";v=\"137\", \"Not/A)Brand\";v=\"24\"",
    "Sec-Ch-Ua-Mobile": "?1",
    "Sec-Ch-Ua-Platform": "\"Android\"",
    "Access-Control-Allow-Origin": "*"
  });

  if (req.method === "POST") {
    try {
      const { encrypted, whatHeader, referer, cookies } = await req.json();
      if (!encrypted || !whatHeader) {
        console.error("Missing encrypted or whatHeader");
        return new Response("Missing encrypted or whatHeader", { status: 400 });
      }
      console.log(`Processing encrypted: ${encrypted.slice(0, 50)}..., whatHeader: ${whatHeader}`);

      // Deserialize and transform
      const deserialized = deserializeBinary(encrypted);
      console.log(`Deserialized: ${deserialized.slice(0, 50)}...`);
      const transformed = transformR(deserialized);
      console.log(`Transformed: ${transformed.slice(0, 50)}...`);

      // Decrypt to get m3u8 path
      const encryptedBytes = new TextEncoder().encode(transformed);
      const decryptedPath = await decryptAES(encryptedBytes, whatHeader);
      console.log(`Raw decrypted path: ${decryptedPath}`);

      // Sanitize and validate path
      const sanitizedPath = sanitizePath(decryptedPath);

      // Construct and validate URL
      const m3u8Url = `https://rr.buytommy.top${sanitizedPath}`;
      try {
        new URL(m3u8Url); // Validate URL
        console.log(`Constructed m3u8 URL: ${m3u8Url}`);
      } catch (e) {
        console.error(`Invalid m3u8 URL: ${m3u8Url}`);
        return new Response(`Invalid URL: ${m3u8Url}`, { status: 400 });
      }

      // Fetch m3u8 playlist
      headers.set("Referer", referer || "https://embedstreams.top");
      if (cookies) headers.set("Cookie", cookies);
      const response = await fetch(m3u8Url, { headers });
      if (!response.ok) {
        console.error(`m3u8 fetch failed: ${response.status}: ${response.statusText}`);
        return new Response(`Failed to fetch m3u8: ${response.statusText}`, { status: response.status });
      }
      let m3u8Content = await response.text();
      if (!m3u8Content.includes("#EXTM3U")) {
        console.error("Invalid m3u8 content");
        return new Response("Invalid M3U8 content", { status: 500 });
      }

      // Rewrite key and segment URLs
      const segmentMap: { [key: string]: string } = {}; // Fixed syntax
      const lines = m3u8Content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith("#EXT-X-KEY") && lines[i].includes("URI=")) {
          const match = lines[i].match(/URI="([^"]+)"/);
          if (match) {
            const originalUri = match[1];
            const fullKeyUrl = new URL(originalUri, m3u8Url).toString();
            const keyPath = originalUri.replace(/^\//, "").replace(/\//g, "_");
            lines[i] = lines[i].replace(originalUri, `/key?key=${encodeURIComponent(fullKeyUrl)}`);
            segmentMap[keyPath] = fullKeyUrl;
            console.log(`Mapping key ${keyPath} to ${fullKeyUrl}`);
          }
        } else if (lines[i].startsWith("https://")) {
          const originalUrl = lines[i];
          const segmentName = originalUrl.split("/").pop()?.replace(/\.js/, ".ts") || `segment_${i}.ts`;
          lines[i] = `/segment?seg=${encodeURIComponent(originalUrl)}`;
          segmentMap[segmentName] = originalUrl;
          console.log(`Mapping segment ${segmentName} to ${originalUrl}`);
        }
      }
      m3u8Content = lines.join("\n");

      // Return proxied URL
      const proxiedUrl = `https://${req.headers.get("host")}/playlist?original=${encodeURIComponent(m3u8Url)}`;
      console.log(`Returning proxied URL: ${proxiedUrl}`);
      return new Response(JSON.stringify({ proxiedUrl }), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        }
      });
    } catch (error) {
      console.error(`POST error: ${req.url}: ${error.message}`);
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  }

  // Handle GET requests for playlist, keys, and segments
  const url = new URL(req.url);
  const originalUrl = url.searchParams.get("original");
  const keyUrl = url.searchParams.get("key");
  const segmentUrl = url.searchParams.get("seg");

  if (originalUrl) {
    try {
      const response = await fetch(originalUrl, { headers });
      if (!response.ok) {
        console.error(`Playlist fetch failed: ${originalUrl}: ${response.statusText}`);
        return new Response(`Failed to fetch m3u8: ${response.statusText}`, { status: response.status });
      }
      let m3u8Content = await response.text();
      const lines = m3u8Content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith("#EXT-X-KEY") && lines[i].includes("URI=")) {
          const match = lines[i].match(/URI="([^"]+)"/);
          if (match) {
            const originalUri = match[1];
            const fullKeyUrl = new URL(originalUri, originalUrl).toString();
            lines[i] = lines[i].replace(originalUri, `/key?key=${encodeURIComponent(fullKeyUrl)}`);
          }
        } else if (lines[i].startsWith("https://")) {
          lines[i] = `/segment?seg=${encodeURIComponent(lines[i])}`;
        }
      }
      m3u8Content = lines.join("\n");
      console.log(`Serving proxied playlist: ${originalUrl}`);
      return new Response(m3u8Content, {
        headers: {
          "Content-Type": "application/vnd.apple.mpegurl",
          "Access-Control-Allow-Origin": "*"
        }
      });
    } catch (error) {
      console.error(`Playlist error: ${originalUrl}: ${error.message}`);
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  } else if (keyUrl || segmentUrl) {
    try {
      const targetUrl = keyUrl || segmentUrl;
      const response = await fetch(targetUrl!, { headers });
      if (!response.ok) {
        console.error(`Resource fetch failed: ${targetUrl}: ${response.statusText}`);
        return new Response(`Failed to fetch resource: ${response.statusText}`, { status: response.status });
      }
      const content = await response.arrayBuffer();
      console.log(`Serving resource: ${targetUrl}`);
      return new Response(content, {
        headers: {
          "Content-Type": response.headers.get("Content-Type") || "application/octet-stream",
          "Access-Control-Allow-Origin": "*"
        }
      });
    } catch (error) {
      console.error(`Resource error: ${targetUrl}: ${error.message}`);
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  }

  console.error(`Not found: ${url}`);
  return new Response("Not Found", { status: 404 });
}, { port: 80 });
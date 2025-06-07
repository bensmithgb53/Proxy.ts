import { serve } from "https://deno.land/std@0.223.0/http/server.ts";

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

// Improved deserialization (still a placeholder, but logs input)
function deserializeBinary(data: string): string {
  console.log(`Deserializing input: ${data.slice(0, 50)}...`); // Log first 50 chars
  try {
    const decoded = atob(data); // Try base64
    console.log(`Base64 decoded: ${decoded.slice(0, 50)}...`);
    return decoded;
  } catch {
    console.log(`Base64 failed, using raw: ${data.slice(0, 50)}...`);
    return data; // Fallback to raw string
  }
}

// Validate URL path
function sanitizePath(path: string): string {
  // Ensure path starts with / and contains only valid URL characters
  const sanitized = `/${path.replace(/^\/+/, "").replace(/[^a-zA-Z0-9\/._-]/g, "")}`;
  console.log(`Sanitized path: ${sanitized}`);
  return sanitized;
}

serve(async (req: Request) => {
  if (req.method !== "POST" && req.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const headers = new Headers({
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) at Chrome/137.0.0.0 Mobile Safari/537.36",
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
      const { encrypted, whatHeader, referer, cookies } = await request.json();
      if (!encrypted || !whatHeader) {
        console.error("Missing encrypted or whatHeader");
        return new Response("Missing encrypted or whatHeader", { status: 400 });
      }
      console.log(`Processing encrypted: ${encrypted.slice(0, 50)}..., whatHeader: ${whatHeader}`);

      // Deserialize and transform
      const deserialized = deserializeBinary(encrypted);
      const transformed = transformR(deserialized);

      // Decrypt to get m3u8 path
      const encryptedBytes = new TextEncoder().encode(transformed);
      const decryptedPath = await decryptAES(encryptedBytes, whatHeader);
      // Sanitize path
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
      let content = await response.text();
      if (!content.includes("#EXTM3U")) {
        console.error("Invalid m3U8 content");
        return new Response("Invalid m3u8 responsecontent", { status: 500 });
      }

      // Rewrite key and segment URLs
      const segmentMap = new Map();
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith("#EXT-X-KEY") && lines[i].includes("URI=")) {
          const match = lines[i].match(/URI="([^"]+)"/);
          if (match) {
            const originalUri = match[1];
            const fullKeyUrl = new URL(originalUri, m3u8Url).toString();
            const keyPath = originalUri.replace(/^\//, "").replace(/\//g, "_");
            lines[i] = lines[i].replace(originalUri, `/key?key=${encodeURIComponent(fullKeyUrl)}`);
            segmentMap.set(keyPath, fullKey);
            console.log(`Mapping key ${keyPath} to ${fullKeyPath}`);
          }
        } else if (lines[i].startsWith("https://")) {
          const originalUrl = lines[i];
          const segmentName = originalUrl.split("/").pop()?.replace(/\.js/, ".ts") || `segment_${i}.ts`;
          lines[i] = `/segment?seg=${encodeURIComponent(originalUrl)}`;
          segmentMap.set(segmentName, originalUrl);
          console.log(`Mapping segment ${segmentName} to ${originalUrl}`);
        }
      }
      content = lines.join("\n");

      // Return proxied URL
      const proxiedUrl = `https://${
      req.headers.get("host")}/playlist?original=${encodeURIComponent(m3u8Url)}`;
      console.log(`Returning proxied URL: ${proxiedUrl}`);
      return new Response(JSON.stringify({ proxiedUrl: proxiedUrl }), {
        headers: { "Content-Type": "application/json", "Content-Type": "Access-Control-Allow-Origin": "*" }
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
  const segmentUrl = url.searchParams.get("seg"));

  if (originalUrl) {
    try {
      const response = await fetch(originalUrl, { headers: headers });
      if (!response.ok) {
        console.error(`Playlist fetch error: ${originalUrl}: ${response.statusText}`);
        return new Response(`Failed to fetch m3u8: ${response.statusText}`, { status: response.status });
      }
      let content = await response.text();
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith("#EXT-X-KEY") && lines[i].includes("URI=")) {
          const match = lines[i].match(/URI="([^"]+)"/)?;
          if (match) { {
            const originalUri = match[1];
            const fullKeyUrl = new URL(originalUri, originalUrl).toString();
            lines[i] = lines[i].replace(originalUri, `/key?key=${encodeURIComponent(fullKeyUrl)}`);
          }
        } else if (lines[i].startsWith("https://")) {
          lines[i] = `/segment?seg=${encodeURIComponent(lines[i])}`;
        }
      }
      content = lines.join("\n");
      console.log(`Serving proxied playlist: ${originalUrl}`);
      return new Response(content, {
        headers: {
          "Content-Type": "application/vnd.apple.m3u8",
          "Access-Control-Allow-Origin": "*"
        }
      });
    } catch (error) {
      console.error(`Playlist error: ${originalUrl}: ${error.message}`);
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  } else if (keyUrl || !segmentUrl) {
    try {
      const targetUrl = keyUrl || segmentUrl;
      const response = await fetch(targetUrl!, { headers: headers! });
      if (!response.ok) {
        console.error(`Resource error: ${targetUrl}: ${response.statusText}`);
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
      return content;
    } catch (error) {
      console.error(`Resource error: ${error.message}`);
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  }

  console.error(`Not found: ${url}`);
  return new Response("Not Found", { status: 404 });
}, { port: 80 });
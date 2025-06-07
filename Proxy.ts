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
}

// Placeholder deserialization (simplified, assumes encrypted is base64 or raw)
function deserializeBinary(data: string): string {
  // bundle.js uses n.deserializeBinary; here we assume base64 for simplicity
  // Replace with actual Protobuf or binary parsing if needed
  try {
    return atob(data); // Try base64 decoding
  } catch {
    return data; // Fallback to raw string
  }
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
        return new Response("Missing encrypted or whatHeader", { status: 400 });
      }
      headers.set("Referer", referer || "https://embedstreams.top");
      if (cookies) headers.set("Cookie", cookies);

      // Deserialize and transform
      const deserialized = deserializeBinary(encrypted);
      const transformed = transformR(deserialized);

      // Decrypt to get m3u8 path
      const encryptedBytes = new TextEncoder().encode(transformed);
      const decryptedPath = await decryptAES(encryptedBytes, whatHeader);
      const m3u8Url = `https://rr.buytommy.top${decryptedPath}`;

      // Fetch m3u8 playlist
      const response = await fetch(m3u8Url, { headers });
      if (!response.ok) {
        return new Response(`Failed to fetch m3u8: ${response.statusText}`, { status: response.status });
      }
      let m3u8Content = await response.text();
      if (!m3u8Content.includes("#EXTM3U")) {
        return new Response("Invalid M3U8 content", { status: 500 });
      }

      // Rewrite key and segment URLs
      const segmentMap: { [key: string]: string } = {};
      const lines = m3u8Content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith("#EXT-X-KEY") && lines[i].includes("URI=")) {
          const originalUri = lines[i].match(/URI="([^"]+)"/)?.[1];
          if (originalUri) {
            const fullKeyUrl = new URL(originalUri, m3u8Url).toString();
            const keyPath = originalUri.replace(/^\//, "").replace(/\//g, "_");
            lines[i] = lines[i].replace(originalUri, `/key?key=${encodeURIComponent(fullKeyUrl)}`);
            segmentMap[keyPath] = fullKeyUrl;
            console.log(`Mapping key ${keyPath} to ${fullKeyUrl}`);
          }
        } else if (lines[i].startsWith("https://")) {
          const originalUrl = lines[i];
          const segmentName = originalUrl.split("/").pop()?.replace(".js", ".ts") || `segment_${i}.ts`;
          lines[i] = `/segment?seg=${encodeURIComponent(originalUrl)}`;
          segmentMap[segmentName] = originalUrl;
          console.log(`Mapping segment ${segmentName} to ${originalUrl}`);
        }
      }
      m3u8Content = lines.join("\n");

      // Return proxied m3u8 URL
      const proxiedUrl = `https://${req.headers.get("host")}/playlist?original=${encodeURIComponent(m3u8Url)}`;
      return new Response(JSON.stringify({ proxiedUrl }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    } catch (error) {
      console.error(`POST error: ${error.message}`);
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
        return new Response(`Failed to fetch m3u8: ${response.statusText}`, { status: response.status });
      }
      let m3u8Content = await response.text();
      const lines = m3u8Content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].startsWith("#EXT-X-KEY") && lines[i].includes("URI=")) {
          const originalUri = lines[i].match(/URI="([^"]+)"/)?.[1];
          if (originalUri) {
            const fullKeyUrl = new URL(originalUri, originalUrl).toString();
            lines[i] = lines[i].replace(originalUri, `/key?key=${encodeURIComponent(fullKeyUrl)}`);
          }
        } else if (lines[i].startsWith("https://")) {
          lines[i] = `/segment?seg=${encodeURIComponent(lines[i])}`;
        }
      }
      m3u8Content = lines.join("\n");
      return new Response(m3u8Content, {
        headers: { "Content-Type": "application/vnd.apple.mpegurl", "Access-Control-Allow-Origin": "*" }
      });
    } catch (error) {
      console.error(`Playlist error: ${error.message}`);
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  } else if (keyUrl || segmentUrl) {
    try {
      const targetUrl = keyUrl || segmentUrl;
      const response = await fetch(targetUrl, { headers });
      if (!response.ok) {
        return new Response(`Failed to fetch resource: ${response.statusText}`, { status: response.status });
      }
      const content = await response.arrayBuffer();
      return new Response(content, {
        headers: { "Content-Type": response.headers.get("Content-Type") || "application/octet-stream", "Access-Control-Allow-Origin": "*" }
      });
    } catch (error) {
      console.error(`Resource error: ${error.message}`);
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  }

  return new Response("Not Found", { status: 404 });
}, { port: 80 });
import { serve } from "https://deno.land/std@0.223.0/http/server.ts";

serve(async (req: Request) => {
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  try {
    const { m3u8Url, referer, cookies } = await req.json();
    if (!m3u8Url || !referer) {
      return new Response("Missing m3u8Url or referer", { status: 400 });
    }

    const headers = new Headers({
      "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
      "Accept": "application/vnd.apple.mpegurl, */*",
      "Referer": referer,
      "Cookie": cookies || "",
      "Origin": "https://embedstreams.top",
      "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
      "Sec-Ch-Ua": "\"Chromium\";v=\"137\", \"Not/A)Brand\";v=\"24\"",
      "Sec-Ch-Ua-Mobile": "?1",
      "Sec-Ch-Ua-Platform": "\"Android\""
    });

    // Fetch m3u8 playlist
    const response = await fetch(m3u8Url, { headers });
    if (!response.ok) {
      return new Response(`Failed to fetch m3u8: ${response.statusText}`, { status: response.status });
    }
    const m3u8Content = await response.text();

    // Check for encryption key
    const keyMatch = m3u8Content.match(/#EXT-X-KEY:METHOD=AES-128,URI="([^"]+)"/);
    if (keyMatch) {
      const keyUrl = new URL(keyMatch[1], m3u8Url).toString();
      const keyResponse = await fetch(keyUrl, { headers });
      if (!keyResponse.ok) {
        return new Response(`Failed to fetch encryption key: ${keyResponse.statusText}`, { status: keyResponse.status });
      }
      // Proxy key through the same server
      const keyProxyUrl = `https://${req.headers.get("host")}/key?key=${encodeURIComponent(keyUrl)}`;
      const proxiedM3u8 = m3u8Content.replace(keyMatch[1], keyProxyUrl);
      return new Response(JSON.stringify({ proxiedUrl: `https://${req.headers.get("host")}/stream?m3u8=${encodeURIComponent(m3u8Url)}` }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Return proxied m3u8 URL
    return new Response(JSON.stringify({ proxiedUrl: `https://${req.headers.get("host")}/stream?m3u8=${encodeURIComponent(m3u8Url)}` }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(`Error: ${error.message}`, { status: 500 });
  }
}, { port: 80 });
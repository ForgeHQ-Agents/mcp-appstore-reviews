#!/usr/bin/env node
// mcp-appstore-reviews — a reviews-only MCP server for the Apple App Store.
//
// The capability boundary IS the trust guarantee: this server exposes ONLY
// read reviews + write/delete a developer response. There is deliberately no
// build, release, submission, pricing, in-app-purchase, certificate, profile,
// or beta-tester tool — adding one would widen what the App Store Connect API
// key can do, so don't. Scope the key narrowly too (least privilege).
//
// Auth: an ES256 JWT is minted on each call from the .p8 private key + issuer
// and key IDs (App Store Connect API). The key is read from the path in
// APP_STORE_CONNECT_PRIVATE_KEY_PATH and is never logged or written elsewhere;
// only the short-lived signed JWT leaves the process, as a Bearer token to Apple.
//
// Dependency-free ESM (Node 18+ global fetch, built-in crypto). Handlers are
// exported for tests; the stdio JSON-RPC loop runs only when executed directly.

import { readFileSync, realpathSync } from "node:fs";
import { sign as cryptoSign } from "node:crypto";
import { fileURLToPath } from "node:url";

const ASC_BASE = "https://api.appstoreconnect.apple.com/v1";
const MAX_RESPONSE_CHARS = 5970; // App Store Connect responseBody maxLength

export const TOOLS = [
  {
    name: "list_reviews",
    description:
      "List customer reviews for an app, newest first by default. Each review includes its id, star rating, title, body, reviewer nickname, territory, date, and the existing developer response (with its id) if one exists. Use the response id with delete_review_response.",
    inputSchema: {
      type: "object",
      properties: {
        appId: {
          type: "string",
          description: "App Store app id (the numeric Apple ID of the app)",
        },
        territory: {
          type: "string",
          description: "Optional ISO territory filter, e.g. 'USA', 'GBR'",
        },
        rating: { type: "number", description: "Optional exact star rating filter, 1–5" },
        sort: {
          type: "string",
          enum: ["recent", "favorable", "critical"],
          description:
            "Sort order: recent (default), favorable (highest first), critical (lowest first)",
        },
        limit: { type: "number", description: "Max reviews to return, 1–200 (default 50)" },
      },
      required: ["appId"],
    },
  },
  {
    name: "respond_to_review",
    description:
      "Publish a public developer response to a customer review. One response per review — if the review already has a response, delete it first with delete_review_response, then respond again.",
    inputSchema: {
      type: "object",
      properties: {
        reviewId: { type: "string", description: "The review id from list_reviews" },
        responseBody: { type: "string", description: "The response text to publish" },
      },
      required: ["reviewId", "responseBody"],
    },
  },
  {
    name: "delete_review_response",
    description:
      "Delete an existing developer response. Takes the response id (the response.id field surfaced by list_reviews), not the review id.",
    inputSchema: {
      type: "object",
      properties: {
        responseId: {
          type: "string",
          description: "The developer-response id from list_reviews",
        },
      },
      required: ["responseId"],
    },
  },
];

const b64url = (input) => Buffer.from(input).toString("base64url");

/**
 * Mint a short-lived ES256 App Store Connect JWT from a .p8 EC private key.
 * `dsaEncoding: "ieee-p1363"` yields the raw r||s signature JWS requires.
 */
export function mintToken({ issuerId, keyId, privateKey }) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "ES256", kid: keyId, typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({ iss: issuerId, iat: now, exp: now + 1200, aud: "appstoreconnect-v1" }),
  );
  const signingInput = `${header}.${payload}`;
  const signature = cryptoSign("sha256", Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${b64url(signature)}`;
}

async function asc(method, path, { token, fetchImpl, body, query }) {
  const url = new URL(`${ASC_BASE}${path}`);
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  }
  const res = await fetchImpl(url.toString(), {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const msg =
      data?.errors?.[0]?.detail ||
      data?.errors?.[0]?.title ||
      `App Store Connect API error ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

const SORT_MAP = { recent: "-createdDate", favorable: "-rating", critical: "rating" };

export async function callTool(name, args, { token, fetchImpl = fetch }) {
  if (!token)
    throw new Error("App Store Connect credentials are not set — the tool is not configured.");
  switch (name) {
    case "list_reviews": {
      if (!args.appId) throw new Error("appId is required");
      const limit = Math.min(Math.max(Number(args.limit) || 50, 1), 200);
      const query = {
        limit,
        sort: SORT_MAP[args.sort] ?? SORT_MAP.recent,
        include: "response",
      };
      if (args.territory) query["filter[territory]"] = args.territory;
      if (args.rating !== undefined) {
        const r = Number(args.rating);
        if (!Number.isInteger(r) || r < 1 || r > 5) {
          throw new Error("rating must be an integer from 1 to 5");
        }
        query["filter[rating]"] = r;
      }
      const data = await asc("GET", `/apps/${encodeURIComponent(args.appId)}/customerReviews`, {
        token,
        fetchImpl,
        query,
      });
      const responses = new Map(
        (data.included ?? [])
          .filter((i) => i.type === "customerReviewResponses")
          .map((i) => [i.id, i]),
      );
      const reviews = (data.data ?? []).map((r) => {
        const respId = r.relationships?.response?.data?.id;
        const resp = respId ? responses.get(respId) : undefined;
        return {
          id: r.id,
          rating: r.attributes?.rating,
          title: r.attributes?.title ?? "",
          body: r.attributes?.body ?? "",
          reviewerNickname: r.attributes?.reviewerNickname ?? "",
          territory: r.attributes?.territory ?? "",
          createdDate: r.attributes?.createdDate ?? "",
          response: resp
            ? {
                id: resp.id,
                body: resp.attributes?.responseBody ?? "",
                state: resp.attributes?.state ?? "",
                lastModified: resp.attributes?.lastModifiedDate ?? "",
              }
            : null,
        };
      });
      return { reviews, count: reviews.length };
    }
    case "respond_to_review": {
      if (!args.reviewId) throw new Error("reviewId is required");
      if (!args.responseBody) throw new Error("responseBody is required");
      if (args.responseBody.length > MAX_RESPONSE_CHARS) {
        throw new Error(`responseBody exceeds the ${MAX_RESPONSE_CHARS}-character App Store limit`);
      }
      const data = await asc("POST", "/customerReviewResponses", {
        token,
        fetchImpl,
        body: {
          data: {
            type: "customerReviewResponses",
            attributes: { responseBody: args.responseBody },
            relationships: {
              review: { data: { type: "customerReviews", id: args.reviewId } },
            },
          },
        },
      });
      return {
        id: data.data?.id,
        state: data.data?.attributes?.state ?? "",
        responseBody: data.data?.attributes?.responseBody ?? "",
      };
    }
    case "delete_review_response": {
      if (!args.responseId) throw new Error("responseId is required");
      await asc("DELETE", `/customerReviewResponses/${encodeURIComponent(args.responseId)}`, {
        token,
        fetchImpl,
      });
      return { deleted: true, id: args.responseId };
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ─── stdio JSON-RPC transport (runs only when executed directly) ───

let cachedKey; // { path, pem } — avoid re-reading + re-parsing the .p8 every call
function readPrivateKey(keyPath) {
  if (cachedKey && cachedKey.path === keyPath) return cachedKey.pem;
  let pem;
  try {
    pem = readFileSync(keyPath, "utf-8");
  } catch {
    // Don't surface the on-disk path to the model.
    throw new Error("Could not read the App Store Connect private key file.");
  }
  cachedKey = { path: keyPath, pem };
  return pem;
}

function tokenFromEnv() {
  const issuerId = process.env.APP_STORE_CONNECT_ISSUER_ID;
  const keyId = process.env.APP_STORE_CONNECT_KEY_ID;
  const keyPath = process.env.APP_STORE_CONNECT_PRIVATE_KEY_PATH;
  if (!issuerId || !keyId || !keyPath) return undefined;
  return mintToken({ issuerId, keyId, privateKey: readPrivateKey(keyPath) });
}

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

async function handle(req) {
  if (req.id === undefined || req.id === null) return; // notifications get no response

  const reply = (result) => send({ jsonrpc: "2.0", id: req.id, result });
  const fail = (code, message) => send({ jsonrpc: "2.0", id: req.id, error: { code, message } });

  switch (req.method) {
    case "initialize":
      return reply({
        protocolVersion: req.params?.protocolVersion || "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "appstore-reviews", version: "1.0.0" },
      });
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: TOOLS });
    case "tools/call": {
      const { name, arguments: args } = req.params ?? {};
      try {
        const result = await callTool(name, args ?? {}, { token: tokenFromEnv() });
        return reply({ content: [{ type: "text", text: JSON.stringify(result, null, 2) }] });
      } catch (err) {
        return reply({
          content: [{ type: "text", text: String(err.message ?? err) }],
          isError: true,
        });
      }
    }
    default:
      return fail(-32601, `Method not found: ${req.method}`);
  }
}

function main() {
  let buffer = "";
  process.stdin.setEncoding("utf-8");
  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    if (buffer.length > 1_000_000) buffer = "";
    let nl;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let req;
      try {
        req = JSON.parse(line);
      } catch {
        continue;
      }
      handle(req).catch(() => {
        if (req && req.id !== undefined && req.id !== null) {
          send({ jsonrpc: "2.0", id: req.id, error: { code: -32603, message: "Internal error" } });
        }
      });
    }
  });
}

// Run only when invoked directly (realpath handles npx/bin symlinks); dormant when imported by tests.
function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMainModule()) main();

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createPublicKey, verify } from "node:crypto";
import { TOOLS, callTool, mintToken } from "../index.mjs";

/** A fetch stub that records calls and replies with `data` (status 200). */
function stubFetch(data) {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({
      url,
      method: opts?.method ?? "GET",
      body: opts?.body ? JSON.parse(opts.body) : undefined,
    });
    return { ok: true, status: 200, text: async () => JSON.stringify(data) };
  };
  return { fetchImpl, calls };
}

const token = "jwt.fake";

test("exposes exactly the three review tools", () => {
  assert.deepEqual(TOOLS.map((t) => t.name).sort(), [
    "delete_review_response",
    "list_reviews",
    "respond_to_review",
  ]);
});

test("exposes NO build/release/pricing/certificate/profile/beta tool", () => {
  const names = TOOLS.map((t) => t.name.toLowerCase());
  for (const forbidden of [
    "build",
    "release",
    "submit",
    "price",
    "certificate",
    "profile",
    "beta",
    "tester",
    "purchase",
    "subscription",
  ]) {
    assert.ok(!names.some((n) => n.includes(forbidden)), `unexpected tool matching "${forbidden}"`);
  }
});

test("list_reviews GETs customerReviews with include=response and maps the response", async () => {
  const { fetchImpl, calls } = stubFetch({
    data: [
      {
        id: "rev1",
        attributes: {
          rating: 5,
          title: "Great",
          body: "Love it",
          reviewerNickname: "Sam",
          territory: "USA",
          createdDate: "2026-06-01",
        },
        relationships: { response: { data: { id: "resp1" } } },
      },
    ],
    included: [
      {
        type: "customerReviewResponses",
        id: "resp1",
        attributes: { responseBody: "Thanks!", state: "PUBLISHED" },
      },
    ],
  });
  const out = await callTool("list_reviews", { appId: "12345", sort: "favorable" }, { token, fetchImpl });
  assert.equal(calls[0].method, "GET");
  assert.ok(calls[0].url.includes("/apps/12345/customerReviews"));
  assert.ok(decodeURIComponent(calls[0].url).includes("include=response"));
  assert.ok(decodeURIComponent(calls[0].url).includes("sort=-rating"));
  assert.equal(out.reviews[0].id, "rev1");
  assert.equal(out.reviews[0].response.id, "resp1");
  assert.equal(out.count, 1);
});

test("respond_to_review POSTs a customerReviewResponses with the review relationship", async () => {
  const { fetchImpl, calls } = stubFetch({
    data: { id: "resp9", attributes: { state: "PENDING_PUBLISH", responseBody: "Hi" } },
  });
  const out = await callTool("respond_to_review", { reviewId: "rev1", responseBody: "Hi" }, { token, fetchImpl });
  assert.equal(calls[0].method, "POST");
  assert.ok(calls[0].url.includes("/customerReviewResponses"));
  assert.equal(calls[0].body.data.attributes.responseBody, "Hi");
  assert.equal(calls[0].body.data.relationships.review.data.id, "rev1");
  assert.equal(out.id, "resp9");
});

test("delete_review_response DELETEs the response by its id", async () => {
  const { fetchImpl, calls } = stubFetch({});
  const out = await callTool("delete_review_response", { responseId: "resp1" }, { token, fetchImpl });
  assert.equal(calls[0].method, "DELETE");
  assert.ok(calls[0].url.includes("/customerReviewResponses/resp1"));
  assert.deepEqual(out, { deleted: true, id: "resp1" });
});

test("errors without credentials, on unknown tool, and on missing required args", async () => {
  const { fetchImpl, calls } = stubFetch({});
  await assert.rejects(() => callTool("list_reviews", { appId: "1" }, { token: undefined }), /not configured/i);
  await assert.rejects(() => callTool("invalid_tool", {}, { token }), /unknown tool/i);
  await assert.rejects(() => callTool("list_reviews", {}, { token, fetchImpl }), /appId is required/i);
  await assert.rejects(() => callTool("respond_to_review", { reviewId: "r" }, { token, fetchImpl }), /responseBody is required/i);
  await assert.rejects(() => callTool("delete_review_response", {}, { token, fetchImpl }), /responseId is required/i);
  assert.equal(calls.length, 0);
});

test("list_reviews rejects an out-of-range rating before calling the API", async () => {
  const { fetchImpl, calls } = stubFetch({});
  await assert.rejects(() => callTool("list_reviews", { appId: "1", rating: 6 }, { token, fetchImpl }), /1 to 5/i);
  await assert.rejects(() => callTool("list_reviews", { appId: "1", rating: 0 }, { token, fetchImpl }), /1 to 5/i);
  assert.equal(calls.length, 0);
});

test("respond_to_review rejects an over-long responseBody before calling the API", async () => {
  const { fetchImpl, calls } = stubFetch({});
  await assert.rejects(
    () => callTool("respond_to_review", { reviewId: "r", responseBody: "x".repeat(5971) }, { token, fetchImpl }),
    /5970-character/i,
  );
  assert.equal(calls.length, 0);
});

test("mints a valid ES256 JWT that verifies against the public key", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" });
  const jwt = mintToken({ issuerId: "iss", keyId: "KID123", privateKey: pem });
  const [h, p, s] = jwt.split(".");
  assert.equal(jwt.split(".").length, 3);
  const header = JSON.parse(Buffer.from(h, "base64url").toString());
  assert.deepEqual(header, { alg: "ES256", kid: "KID123", typ: "JWT" });
  const payload = JSON.parse(Buffer.from(p, "base64url").toString());
  assert.equal(payload.iss, "iss");
  assert.equal(payload.aud, "appstoreconnect-v1");
  const pub = createPublicKey(pem);
  const ok = verify("sha256", Buffer.from(`${h}.${p}`), { key: pub, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
  assert.ok(ok, "ES256 signature should verify");
});

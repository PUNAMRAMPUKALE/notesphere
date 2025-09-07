// ---------- Notes Service with Search (Elasticsearch) + Attachments (MinIO/S3) ----------
// Every line below is commented to explain exactly what it does.

import express from "express"; // Web framework for defining HTTP routes.
import { Pool } from "pg"; // PostgreSQL connection pool.
import jwt from "jsonwebtoken"; // JSON Web Token utilities (sign/verify).
import { Client as ESClient } from "@elastic/elasticsearch"; // Elasticsearch client.
import {
  S3Client, // AWS SDK v3 S3 client (works with MinIO).
  PutObjectCommand, // Command to upload objects (used for presigned PUT).
  GetObjectCommand, // Command to download objects (used for presigned GET).
  HeadBucketCommand, // Command to check if a bucket exists.
  CreateBucketCommand, // Command to create a bucket if missing.
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner"; // Helper to create presigned URLs.
import { randomUUID } from "crypto"; // Helper to generate unique IDs for file names.

const app = express(); // Create an Express application instance.
app.use(express.json()); // Parse incoming JSON bodies on requests.

// --------------------------- Environment & Client Setup ---------------------------

const PORT = Number(process.env.PORT ?? 3002); // Port the notes service listens on (default 3002).
const DATABASE_URL = process.env.DATABASE_URL!; // Postgres connection string (must be provided).
const JWT_SECRET = process.env.JWT_SECRET ?? "dev-secret"; // Secret for verifying JWTs (dev default).

const ELASTIC_URL = process.env.ELASTIC_URL || "http://elasticsearch:9200"; // Internal URL for Elasticsearch.
const MINIO_ENDPOINT = process.env.MINIO_ENDPOINT || "http://minio:9000"; // Internal MinIO URL (Docker network).
const MINIO_PUBLIC_ENDPOINT = process.env.MINIO_PUBLIC_ENDPOINT || "http://localhost:9000"; // External URL for browser.
const MINIO_ACCESS_KEY = process.env.MINIO_ACCESS_KEY || "minio"; // MinIO access key (username).
const MINIO_SECRET_KEY = process.env.MINIO_SECRET_KEY || "minio123"; // MinIO secret key (password).
const MINIO_BUCKET = process.env.MINIO_BUCKET || "notes-uploads"; // Bucket where attachments are stored.

const pool = new Pool({ connectionString: DATABASE_URL }); // Create a Postgres connection pool.
const es = new ESClient({ node: ELASTIC_URL }); // Create an Elasticsearch client pointing to ES url.

// Two S3 clients: one for internal server ops, one that signs URLs usable in a browser.
const s3Internal = new S3Client({
  region: "us-east-1", // Arbitrary for MinIO; must be consistent.
  endpoint: MINIO_ENDPOINT, // Internal Docker address (minio:9000).
  forcePathStyle: true, // Required for MinIO path-style addressing.
  credentials: { accessKeyId: MINIO_ACCESS_KEY, secretAccessKey: MINIO_SECRET_KEY }, // MinIO credentials.
});

const s3Public = new S3Client({
  region: "us-east-1", // Same region for consistency.
  endpoint: MINIO_PUBLIC_ENDPOINT, // Public address (localhost:9000) so links work in your browser.
  forcePathStyle: true, // Required for MinIO path-style addressing.
  credentials: { accessKeyId: MINIO_ACCESS_KEY, secretAccessKey: MINIO_SECRET_KEY }, // Same credentials.
});

// --------------------------- One-time Ensure: Index & Bucket ---------------------------

async function ensureSearchIndex() {
  // Create the "notes" index with mapping if it doesn't exist (ignore 400 = already exists).
  try {
    await es.indices.create(
      {
        index: "notes", // Index name in Elasticsearch.
        mappings: {
          properties: {
            user_id: { type: "keyword" }, // Exact-match user filter (not analyzed).
            title: { type: "text" }, // Full-text searchable title.
            body: { type: "text" }, // Full-text searchable body.
            updated_at: { type: "date" }, // Timestamp for sorting/recency.
          },
        },
      },
      { ignore: [400] } // Do not throw if index already exists.
    );
  } catch (e) {
    console.error("ensureIndex error:", e); // Log any unexpected errors.
  }
}

async function ensureBucket() {
  // Ensure the S3 bucket exists; create it if HeadBucket fails.
  try {
    await s3Internal.send(new HeadBucketCommand({ Bucket: MINIO_BUCKET })); // Check if bucket exists.
  } catch {
    try {
      await s3Internal.send(new CreateBucketCommand({ Bucket: MINIO_BUCKET })); // Create if missing.
    } catch (e) {
      console.error("ensureBucket error:", e); // Log errors creating bucket.
    }
  }
}

ensureSearchIndex(); // Kick off ES index ensure (fire-and-forget).
ensureBucket(); // Kick off bucket ensure (fire-and-forget).

// --------------------------- Health Endpoints ---------------------------

app.get("/health", (_req, res) => res.json({ service: "notes", ok: true })); // Simple health for direct container access.
app.get("/notes/health", (_req, res) => res.json({ service: "notes", ok: true })); // Health when routed through gateway /notes.

// --------------------------- Auth Middleware (JWT) ---------------------------

function auth(req: any, res: any, next: any) {
  // Minimal JWT middleware: expects Authorization: Bearer <token>.
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", ""); // Extract token from header.
    req.user = jwt.verify(token, JWT_SECRET); // Verify token and attach payload to req.user.
    next(); // Continue to the route handler.
  } catch {
    res.status(401).json({ error: "unauthorized" }); // If missing/invalid, return 401.
  }
}

// --------------------------- Notes: List & Create ---------------------------

app.get("/notes", auth, async (req: any, res) => {
  // Return most recent notes for the authenticated user (limit 50).
  const { userId } = req.user; // Extract user id from verified JWT.
  const q = await pool.query(
    "SELECT id, title, body, updated_at FROM notes WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 50", // Query by user id.
    [userId] // Parameterized to avoid SQL injection.
  );
  res.json(q.rows); // Send rows as JSON array.
});

app.post("/notes", auth, async (req: any, res) => {
  // Create a note in Postgres, then index it into Elasticsearch (best-effort).
  const { userId } = req.user; // Authenticated user's id.
  const { title, body } = req.body || {}; // Extract note fields from JSON body.
  const q = await pool.query(
    "INSERT INTO notes (user_id, title, body) VALUES ($1,$2,$3) RETURNING id, now() AS now_ts", // Insert and return id+timestamp.
    [userId, title, body] // Parameterized values.
  );
  const newId = q.rows[0].id; // New note ID (UUID).
  const nowIso = new Date(q.rows[0].now_ts ?? Date.now()).toISOString(); // ISO timestamp for ES doc.

  try {
    await es.index({
      index: "notes", // Target ES index.
      id: newId, // Use Postgres UUID as ES document id.
      document: { user_id: userId, title, body, updated_at: nowIso }, // Document body stored in ES.
    });
  } catch (e) {
    console.error("index note error:", e); // Do not fail the API if ES indexing fails.
  }

  res.status(201).json({ id: newId }); // Return the new note id.
});

// --------------------------- Notes: Full-text Search ---------------------------

app.get("/notes/search", auth, async (req: any, res) => {
  // Search notes by query string across title/body, filtered to the current user.
  const { userId } = req.user; // Current authenticated user id.
  const query = String(req.query.q || "").trim(); // Read ?q= from query string.
  if (!query) return res.json([]); // Empty query returns empty array (fast path).

  try {
    const result = await es.search({
      index: "notes", // Search the "notes" index.
      size: 20, // Max number of results to return.
      query: {
        bool: {
          must: [{ multi_match: { query, fields: ["title^2", "body"] } }], // Boost title field.
          filter: [{ term: { user_id: userId } }], // Restrict to this user's notes.
        },
      },
    });

    const hits = (result.hits.hits as any[]).map((h) => ({
      id: h._id, // ES document id (same as note id).
      score: h._score, // Relevance score from ES.
      ...(h._source as object), // Spread original document fields.
    }));
    res.json(hits); // Return array of hits.
  } catch (e) {
    console.error("search error:", e); // Log ES errors for debugging.
    res.status(500).json({ error: "search_failed" }); // Standardized error response.
  }
});

// --------------------------- Attachments Helpers ---------------------------

async function assertOwnsNote(noteId: string, userId: string) {
  // Ensure the note belongs to the given user; throw 404 if it does not.
  const r = await pool.query("SELECT 1 FROM notes WHERE id=$1 AND user_id=$2", [noteId, userId]); // Ownership check.
  if (r.rowCount === 0) {
    const err: any = new Error("not_found"); // Create a typed error.
    err.status = 404; // Use 404 to avoid leaking existence information.
    throw err; // Throw to be caught by callers.
  }
}

// --------------------------- Attachments: Presign Upload ---------------------------

app.post("/notes/:noteId/attachments/presign", auth, async (req: any, res) => {
  // Issue a presigned PUT URL so the client can upload to MinIO directly.
  const { userId } = req.user; // Authenticated user's id.
  const { noteId } = req.params; // Note id from URL path.
  const { filename = "upload.bin", contentType = "application/octet-stream" } = req.body || {}; // File metadata.

  try {
    await assertOwnsNote(noteId, userId); // Ensure the user owns this note.

    const safeName = String(filename).replace(/[^\w.\-]+/g, "_"); // Sanitize filename for storage.
    const key = `${userId}/${noteId}/${randomUUID()}_${safeName}`; // Object key: user/note/uuid_filename.

    const ins = await pool.query(
      "INSERT INTO attachments (note_id, user_id, object_key, content_type) VALUES ($1,$2,$3,$4) RETURNING id", // Insert attachment row.
      [noteId, userId, key, contentType] // Values for insert.
    );
    const attachmentId = ins.rows[0].id; // DB id for the attachment row.

    const putCmd = new PutObjectCommand({
      Bucket: MINIO_BUCKET, // Bucket to upload to.
      Key: key, // Object path inside the bucket.
      ContentType: contentType, // MIME type (helps browser/clients).
    });
    const uploadUrl = await getSignedUrl(s3Public, putCmd, { expiresIn: 900 }); // Create a 15-min presigned PUT URL.

    res.status(201).json({ attachmentId, objectKey: key, uploadUrl }); // Return URL + ids to the client.
  } catch (e: any) {
    const code = e.status || 500; // Choose 404 if thrown, else 500.
    res.status(code).json({ error: e.message || "presign_failed" }); // Return error to client.
  }
});

// --------------------------- Attachments: Mark Complete ---------------------------

app.post("/notes/attachments/:attachmentId/complete", auth, async (req: any, res) => {
  // Optionally record the object size after client uploads the file.
  const { userId } = req.user; // Authenticated user id.
  const { attachmentId } = req.params; // Attachment row id.
  const { sizeBytes = null } = req.body || {}; // Size provided by client (optional).

  const r = await pool.query(
    "UPDATE attachments SET size_bytes=$1 WHERE id=$2 AND user_id=$3 RETURNING id", // Update row size if ownership matches.
    [sizeBytes, attachmentId, userId] // Parameterized args.
  );
  if (r.rowCount === 0) return res.status(404).json({ error: "not_found" }); // 404 if not owned/not found.
  res.json({ ok: true }); // Success response.
});

// --------------------------- Attachments: List For a Note ---------------------------

app.get("/notes/:noteId/attachments", auth, async (req: any, res) => {
  // List attachments for a given note, most recent first.
  const { userId } = req.user; // Authenticated user id.
  const { noteId } = req.params; // Note id to list attachments for.
  await assertOwnsNote(noteId, userId); // Ensure user owns the note.

  const q = await pool.query(
    "SELECT id, object_key, content_type, size_bytes, created_at FROM attachments WHERE note_id=$1 AND user_id=$2 ORDER BY created_at DESC", // Query rows.
    [noteId, userId] // Params to ensure user scoping.
  );
  res.json(q.rows); // Return rows as JSON.
});

// --------------------------- Attachments: Presign Download ---------------------------

app.get("/notes/attachments/:attachmentId/url", auth, async (req: any, res) => {
  // Issue a presigned GET URL so the client can download the file.
  const { userId } = req.user; // Authenticated user id.
  const { attachmentId } = req.params; // Attachment row id.

  const q = await pool.query(
    "SELECT object_key, content_type FROM attachments WHERE id=$1 AND user_id=$2", // Fetch object key & type.
    [attachmentId, userId] // Ensure user owns this attachment.
  );
  if (q.rowCount === 0) return res.status(404).json({ error: "not_found" }); // 404 if not found.
  const { object_key, content_type } = q.rows[0]; // Extract DB values.

  const getCmd = new GetObjectCommand({ Bucket: MINIO_BUCKET, Key: object_key }); // Prepare GET command.
  const url = await getSignedUrl(s3Public, getCmd, { expiresIn: 600 }); // Create a 10-min presigned GET URL.
  res.json({ url, contentType: content_type }); // Return URL so the client can download.
});

// --------------------------- Server Boot ---------------------------

app.listen(PORT, () => console.log(`notes listening on ${PORT}`)); // Start HTTP server and log port.

// ---------- Notes Service with Search (Elasticsearch) + Attachments (MinIO/S3) + Update/Delete/Pagination ----------
// Every line below is commented so you can understand and explain each piece confidently.

import express from "express"; // Web framework for defining HTTP routes.
import { Pool } from "pg"; // PostgreSQL connection pool for DB queries.
import jwt from "jsonwebtoken"; // JSON Web Token utilities (verify signed tokens).
import { Client as ESClient } from "@elastic/elasticsearch"; // Elasticsearch JS client.
import {
  S3Client,               // AWS SDK v3 S3 client (compatible with MinIO).
  PutObjectCommand,       // Command used to generate presigned PUT (upload).
  GetObjectCommand,       // Command used to generate presigned GET (download).
  HeadBucketCommand,      // Command to check bucket existence.
  CreateBucketCommand,    // Command to create bucket if it's missing.
  ListObjectsV2Command,   // ⬅ To list objects under a prefix (for cleanup).
  DeleteObjectsCommand    // ⬅ To delete a batch of objects from the bucket.
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner"; // Helper to create presigned URLs.
import { randomUUID } from "crypto"; // Generates unique IDs; used in object keys.

const app = express(); // Create an Express app instance.
app.use(express.json()); // Enable JSON body parsing for incoming requests.

// --------------------------- Environment & Client Setup ---------------------------

const PORT = Number(process.env.PORT ?? 3002); // Service port (default 3002).
const DATABASE_URL = process.env.DATABASE_URL!; // Postgres connection string (required).
const JWT_SECRET = process.env.JWT_SECRET ?? "dev-secret"; // Secret for verifying JWTs (dev fallback).

const ELASTIC_URL = process.env.ELASTIC_URL || "http://elasticsearch:9200"; // Internal URL for Elasticsearch.
const MINIO_ENDPOINT = process.env.MINIO_ENDPOINT || "http://minio:9000"; // Internal MinIO endpoint (Docker network).
const MINIO_PUBLIC_ENDPOINT = process.env.MINIO_PUBLIC_ENDPOINT || "http://localhost:9000"; // Public MinIO endpoint (browser).
const MINIO_ACCESS_KEY = process.env.MINIO_ACCESS_KEY || "minio"; // MinIO access key.
const MINIO_SECRET_KEY = process.env.MINIO_SECRET_KEY || "minio123"; // MinIO secret key.
const MINIO_BUCKET = process.env.MINIO_BUCKET || "notes-uploads"; // S3 bucket name for attachments.

const pool = new Pool({ connectionString: DATABASE_URL }); // Initialize Postgres pool.
const es = new ESClient({ node: ELASTIC_URL }); // Initialize ES client to the given node.

// Two S3 clients: internal for server ops; public for presigned URLs that your browser can open.
const s3Internal = new S3Client({
  region: "us-east-1", // Arbitrary but consistent region for MinIO.
  endpoint: MINIO_ENDPOINT, // Internal endpoint reachable by containers.
  forcePathStyle: true, // Required by MinIO (path-style addressing).
  credentials: { accessKeyId: MINIO_ACCESS_KEY, secretAccessKey: MINIO_SECRET_KEY }, // MinIO creds.
});
const s3Public = new S3Client({
  region: "us-east-1", // Same region.
  endpoint: MINIO_PUBLIC_ENDPOINT, // Public endpoint reachable by your Mac/browser.
  forcePathStyle: true, // Required by MinIO.
  credentials: { accessKeyId: MINIO_ACCESS_KEY, secretAccessKey: MINIO_SECRET_KEY }, // Same creds.
});

// --------------------------- One-time Ensure: Index & Bucket ---------------------------

async function ensureSearchIndex() {
  // Ensure the Elasticsearch "notes" index exists with correct mapping.
  try {
    await es.indices.create(
      {
        index: "notes", // Index name.
        mappings: {
          properties: {
            user_id: { type: "keyword" }, // Exact-match filter (not analyzed).
            title: { type: "text" }, // Full-text searchable title.
            body: { type: "text" }, // Full-text searchable body.
            updated_at: { type: "date" }, // For sorting/recency.
          },
        },
      },
      { ignore: [400] } // Ignore "already exists" errors.
    );
  } catch (e) {
    console.error("ensureIndex error:", e); // Log any unexpected errors.
  }
}

async function ensureBucket() {
  // Ensure the MinIO bucket exists; create if missing.
  try {
    await s3Internal.send(new HeadBucketCommand({ Bucket: MINIO_BUCKET })); // Probe bucket existence.
  } catch {
    try {
      await s3Internal.send(new CreateBucketCommand({ Bucket: MINIO_BUCKET })); // Create when absent.
    } catch (e) {
      console.error("ensureBucket error:", e); // Log bucket creation errors.
    }
  }
}

ensureSearchIndex(); // Fire-and-forget ES index ensure.
ensureBucket(); // Fire-and-forget MinIO bucket ensure.

// --------------------------- Health Endpoints ---------------------------

app.get("/health", (_req, res) => res.json({ service: "notes", ok: true })); // Direct container health check.
app.get("/notes/health", (_req, res) => res.json({ service: "notes", ok: true })); // Health via /notes prefix (through gateway).

// --------------------------- Auth Middleware (JWT) ---------------------------

function auth(req: any, res: any, next: any) {
  // Minimal JWT middleware: expects Authorization: Bearer <token>.
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", ""); // Pull token from header.
    req.user = jwt.verify(token, JWT_SECRET); // Verify token; attach payload to req.user.
    next(); // Continue to handler.
  } catch {
    res.status(401).json({ error: "unauthorized" }); // Return 401 if invalid/missing.
  }
}

// --------------------------- Notes: List (Pagination) & Create ---------------------------

app.get("/notes", auth, async (req: any, res) => {
  // List notes with simple pagination (?limit=&offset=) for the authenticated user.
  const { userId } = req.user; // Get user id from JWT.
  const limit = Math.min(Math.max(parseInt(String(req.query.limit ?? "20"), 10) || 20, 1), 100); // Clamp 1..100.
  const offset = Math.max(parseInt(String(req.query.offset ?? "0"), 10) || 0, 0); // Non-negative offset.

  const q = await pool.query(
    `SELECT id, title, body, updated_at
       FROM notes
      WHERE user_id=$1
      ORDER BY updated_at DESC
      LIMIT $2 OFFSET $3`, // Page results by limit/offset.
    [userId, limit, offset] // Parameters to avoid SQL injection.
  );

  const c = await pool.query(
    `SELECT COUNT(*)::int AS count FROM notes WHERE user_id=$1`, // Get total count for UI pagination.
    [userId]
  );

  res.json({ items: q.rows, total: c.rows[0].count, limit, offset }); // Return paged items + metadata.
});

app.post("/notes", auth, async (req: any, res) => {
  // Create a new note, then index it in Elasticsearch (best-effort).
  const { userId } = req.user; // Authenticated user id.
  const { title, body } = req.body || {}; // Extract fields from JSON body.
  const q = await pool.query(
    "INSERT INTO notes (user_id, title, body) VALUES ($1,$2,$3) RETURNING id, now() AS now_ts", // Insert + return id/timestamp.
    [userId, title, body] // Parameterized values.
  );

  const newId = q.rows[0].id; // Newly created note id.
  const nowIso = new Date(q.rows[0].now_ts ?? Date.now()).toISOString(); // Convert timestamp to ISO.

  try {
    await es.index({
      index: "notes", // Index name.
      id: newId, // Use same id as DB (easy consistency).
      document: { user_id: userId, title, body, updated_at: nowIso }, // ES doc body.
    });
  } catch (e) {
    console.error("index note error:", e); // Don’t fail request if ES is temporarily down.
  }

  res.status(201).json({ id: newId }); // Respond with new note id.
});

// --------------------------- Notes: Update & Delete ---------------------------

app.put("/notes/:id", auth, async (req: any, res) => {
  // Update title/body for a note you own; reindex in ES on success.
  const { userId } = req.user; // Authenticated user id.
  const { id } = req.params; // Note id to update.
  const { title, body } = req.body || {}; // Optional fields to update.

  const q = await pool.query(
    `UPDATE notes
        SET title = COALESCE($1, title),      -- Only change if provided
            body  = COALESCE($2, body),
            updated_at = now()
      WHERE id=$3 AND user_id=$4
    RETURNING id, title, body, updated_at`, // Return updated row.
    [title ?? null, body ?? null, id, userId] // Parameterized values.
  );

  if (q.rowCount === 0) return res.status(404).json({ error: "not_found" }); // Either note doesn't exist or not yours.

  try {
    await es.index({
      index: "notes", // Reindex the updated doc.
      id, // Same id as before.
      document: {
        user_id: userId,
        title: q.rows[0].title,
        body: q.rows[0].body,
        updated_at: new Date(q.rows[0].updated_at).toISOString(),
      },
    });
  } catch (e) {
    console.error("es reindex on update:", e); // Log ES issues but don't fail API.
  }

  res.json(q.rows[0]); // Return the updated note.
});

app.delete("/notes/:id", auth, async (req: any, res) => {
  // Delete a note you own:
  //  1) Best-effort delete all MinIO objects under prefix userId/noteId/
  //  2) Delete DB row (attachments are removed via FK CASCADE)
  //  3) Best-effort delete from Elasticsearch
  const { userId } = req.user; // Authenticated user id.
  const { id } = req.params; // Note id to delete.

  // --- Step 1: delete all objects in MinIO under this note's prefix ---
  const prefix = `${userId}/${id}/`; // We store attachments as userId/noteId/<uuid>_filename
  try {
    const toDelete: { Key: string }[] = []; // Collect keys to delete.

    // List may be truncated; loop with continuation.
    let ContinuationToken: string | undefined = undefined;
    do {
      const list:any = await s3Internal.send(new ListObjectsV2Command({
        Bucket: MINIO_BUCKET,
        Prefix: prefix,
        ContinuationToken
      }));
      (list.Contents || []).forEach((obj: { Key: any; }) => obj.Key && toDelete.push({ Key: obj.Key }));
      ContinuationToken = list.IsTruncated ? list.NextContinuationToken : undefined;
    } while (ContinuationToken);

    // Delete in batches of up to 1000 keys (S3 API limit).
    for (let i = 0; i < toDelete.length; i += 1000) {
      const batch = toDelete.slice(i, i + 1000);
      if (batch.length > 0) {
        await s3Internal.send(new DeleteObjectsCommand({
          Bucket: MINIO_BUCKET,
          Delete: { Objects: batch }
        }));
      }
    }
  } catch (e) {
    console.error("minio delete objects error:", e); // If MinIO fails, still proceed with DB/ES.
  }

  // --- Step 2: delete the note row (and cascade attachments rows) ---
  const del = await pool.query(
    `DELETE FROM notes WHERE id=$1 AND user_id=$2 RETURNING id`, // Only delete if you own it.
    [id, userId]
  );
  if (del.rowCount === 0) return res.status(404).json({ error: "not_found" }); // Not found or not owned.

  // --- Step 3: best-effort ES delete ---
  try {
    await es.delete({ index: "notes", id }); // Remove search doc; ignore if 404 happens.
  } catch (e) {
    console.error("es delete on note delete:", e); // Log and continue.
  }

  res.status(204).end(); // No Content on successful deletion.
});

// --------------------------- Notes: Full-text Search ---------------------------

app.get("/notes/search", auth, async (req: any, res) => {
  // Search across your notes' title/body with ES, filtered by your user id.
  const { userId } = req.user; // Authenticated user id.
  const query = String(req.query.q || "").trim(); // Read ?q= query param.
  if (!query) return res.json([]); // Return empty if no query string.

  try {
    const result = await es.search({
      index: "notes", // Index to search.
      size: 20, // Max results.
      query: {
        bool: {
          must: [{ multi_match: { query, fields: ["title^2", "body"] } }], // Boost title relevance.
          filter: [{ term: { user_id: userId } }], // Restrict to current user's notes.
        },
      },
    });

    const hits = (result.hits.hits as any[]).map((h) => ({
      id: h._id, // ES doc id (same as DB id).
      score: h._score, // Relevance score.
      ...(h._source as object), // Original fields.
    }));
    res.json(hits); // Return hit list.
  } catch (e) {
    console.error("search error:", e); // Log ES error details.
    res.status(500).json({ error: "search_failed" }); // Consistent error shape.
  }
});

// --------------------------- Attachments Helpers ---------------------------

async function assertOwnsNote(noteId: string, userId: string) {
  // Verify the note belongs to this user to prevent cross-user access.
  const r = await pool.query("SELECT 1 FROM notes WHERE id=$1 AND user_id=$2", [noteId, userId]); // Ownership check.
  if (r.rowCount === 0) {
    const err: any = new Error("not_found"); // Do not reveal note existence across users.
    err.status = 404; // Use 404 for security (not 403).
    throw err; // Let caller handle as 404.
  }
}

// --------------------------- Attachments: Presign Upload ---------------------------

app.post("/notes/:noteId/attachments/presign", auth, async (req: any, res) => {
  // Request a presigned PUT URL to upload directly to MinIO from the client.
  const { userId } = req.user; // Authenticated user id.
  const { noteId } = req.params; // Note id path param.
  const { filename = "upload.bin", contentType = "application/octet-stream" } = req.body || {}; // File meta.

  try {
    await assertOwnsNote(noteId, userId); // Ensure user owns the target note.

    const safeName = String(filename).replace(/[^\w.\-]+/g, "_"); // Sanitize filename for S3 key compatibility.
    const key = `${userId}/${noteId}/${randomUUID()}_${safeName}`; // S3 object key: user/note/uuid_filename.

    const ins = await pool.query(
      "INSERT INTO attachments (note_id, user_id, object_key, content_type) VALUES ($1,$2,$3,$4) RETURNING id", // Insert DB row.
      [noteId, userId, key, contentType]
    );
    const attachmentId = ins.rows[0].id; // Primary key of attachment row.

    const putCmd = new PutObjectCommand({
      Bucket: MINIO_BUCKET, // Target bucket.
      Key: key, // Object key/path.
      ContentType: contentType, // MIME type for the upload.
    });
    const uploadUrl = await getSignedUrl(s3Public, putCmd, { expiresIn: 900 }); // 15-min presigned PUT URL (browser-friendly).

    res.status(201).json({ attachmentId, objectKey: key, uploadUrl }); // Return info to client for upload.
  } catch (e: any) {
    const code = e.status || 500; // Map thrown 404 or default 500.
    res.status(code).json({ error: e.message || "presign_failed" }); // Return error payload.
  }
});

// --------------------------- Attachments: Mark Complete ---------------------------

app.post("/notes/attachments/:attachmentId/complete", auth, async (req: any, res) => {
  // Optionally record the size after upload completes (handy for UI/limits).
  const { userId } = req.user; // Authenticated user id.
  const { attachmentId } = req.params; // Attachment id.
  const { sizeBytes = null } = req.body || {}; // Optional file size.

  const r = await pool.query(
    "UPDATE attachments SET size_bytes=$1 WHERE id=$2 AND user_id=$3 RETURNING id", // Ownership enforced in SQL.
    [sizeBytes, attachmentId, userId]
  );
  if (r.rowCount === 0) return res.status(404).json({ error: "not_found" }); // 404 if not owned/not found.
  res.json({ ok: true }); // Success response.
});

// --------------------------- Attachments: List For a Note ---------------------------

app.get("/notes/:noteId/attachments", auth, async (req: any, res) => {
  // List attachments for a note you own (newest first).
  const { userId } = req.user; // Authenticated user id.
  const { noteId } = req.params; // Note id to list for.

  await assertOwnsNote(noteId, userId); // Ensure ownership first.

  const q = await pool.query(
    "SELECT id, object_key, content_type, size_bytes, created_at FROM attachments WHERE note_id=$1 AND user_id=$2 ORDER BY created_at DESC", // Query attachments.
    [noteId, userId]
  );
  res.json(q.rows); // Return rows as JSON array.
});

// --------------------------- Attachments: Presign Download ---------------------------

app.get("/notes/attachments/:attachmentId/url", auth, async (req: any, res) => {
  // Get a presigned GET URL so the client can download the file via browser.
  const { userId } = req.user; // Authenticated user id.
  const { attachmentId } = req.params; // Attachment id to download.

  const q = await pool.query(
    "SELECT object_key, content_type FROM attachments WHERE id=$1 AND user_id=$2", // Enforce ownership in SQL.
    [attachmentId, userId]
  );
  if (q.rowCount === 0) return res.status(404).json({ error: "not_found" }); // 404 if not found/owned.

  const { object_key, content_type } = q.rows[0]; // Extract key/type.

  const getCmd = new GetObjectCommand({ Bucket: MINIO_BUCKET, Key: object_key }); // Prepare S3 GET command.
  const url = await getSignedUrl(s3Public, getCmd, { expiresIn: 600 }); // 10-min presigned GET URL (browser-friendly).
  res.json({ url, contentType: content_type }); // Return download URL and MIME type.
});

// --------------------------- Server Boot ---------------------------

app.listen(PORT, () => console.log(`notes listening on ${PORT}`)); // Start HTTP server and log the port.

import express from "express";
import { Pool } from "pg";
import jwt from "jsonwebtoken";
import { Client } from "@elastic/elasticsearch";

const app = express();
app.use(express.json());

// Env / clients
const PORT = Number(process.env.PORT ?? 3002);
const DATABASE_URL = process.env.DATABASE_URL!;
const JWT_SECRET = process.env.JWT_SECRET ?? "dev-secret";
const ELASTIC_URL = process.env.ELASTIC_URL || "http://elasticsearch:9200";

const pool = new Pool({ connectionString: DATABASE_URL });
const es = new Client({ node: ELASTIC_URL });

// Ensure ES index exists (safe if already created)
async function ensureIndex() {
  try {
    await es.indices.create(
      {
        index: "notes",
        mappings: {
          properties: {
            user_id:    { type: "keyword" },
            title:      { type: "text" },
            body:       { type: "text" },
            updated_at: { type: "date" }
          }
        }
      },
      { ignore: [400] } // 400 = index already exists
    );
  } catch (e) {
    console.error("ensureIndex error:", e);
  }
}
ensureIndex();

// Health (works with or without /notes prefix via gateway)
app.get("/health", (_req, res) => res.json({ service: "notes", ok: true }));
app.get("/notes/health", (_req, res) => res.json({ service: "notes", ok: true }));

// Tiny auth middleware (JWT in Authorization: Bearer <token>)
function auth(req: any, res: any, next: any) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "unauthorized" });
  }
}

// List latest notes
app.get("/notes", auth, async (req: any, res) => {
  const { userId } = req.user;
  const q = await pool.query(
    "SELECT id, title, body, updated_at FROM notes WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 50",
    [userId]
  );
  res.json(q.rows);
});

// Create a note (DB insert + index into Elasticsearch)
app.post("/notes", auth, async (req: any, res) => {
  const { userId } = req.user;
  const { title, body } = req.body || {};
  const q = await pool.query(
    "INSERT INTO notes (user_id, title, body) VALUES ($1,$2,$3) RETURNING id, now() AS now_ts",
    [userId, title, body]
  );
  const newId = q.rows[0].id;
  const nowIso = new Date(q.rows[0].now_ts ?? Date.now()).toISOString();

  // Best-effort ES index (don't fail the request if ES is down)
  try {
    await es.index({
      index: "notes",
      id: newId,
      document: { user_id: userId, title, body, updated_at: nowIso }
    });
  } catch (e) {
    console.error("index note error:", e);
  }

  res.status(201).json({ id: newId });
});

// Full-text search across user's notes
// Example: GET /notes/search?q=tahoe
app.get("/notes/search", auth, async (req: any, res) => {
  const { userId } = req.user;
  const query = String(req.query.q || "").trim();
  if (!query) return res.json([]);

  try {
    const result = await es.search({
      index: "notes",
      size: 20,
      query: {
        bool: {
          must: [{ multi_match: { query, fields: ["title^2", "body"] } }],
          filter: [{ term: { user_id: userId } }]
        }
      }
    });

    const hits = (result.hits.hits as any[]).map(h => ({
      id: h._id,
      score: h._score,
      ...(h._source as object)
    }));
    res.json(hits);
  } catch (e) {
    console.error("search error:", e);
    res.status(500).json({ error: "search_failed" });
  }
});

// Re-index all of the current user's notes into Elasticsearch (backfill)
app.post("/notes/reindex", auth, async (req: any, res) => {
  const { userId } = req.user;
  const q = await pool.query(
    "SELECT id, title, body, updated_at FROM notes WHERE user_id=$1 ORDER BY updated_at DESC",
    [userId]
  );

  const ops = q.rows.map((row: any) => {
    const updatedIso = row.updated_at
      ? new Date(row.updated_at).toISOString()
      : new Date().toISOString();
    return es.index({
      index: "notes",
      id: row.id,
      document: {
        user_id: userId,
        title: row.title,
        body: row.body,
        updated_at: updatedIso
      }
    });
  });

  await Promise.allSettled(ops);
  res.json({ indexed: q.rowCount });
});

app.listen(PORT, () => console.log(`notes listening on ${PORT}`));

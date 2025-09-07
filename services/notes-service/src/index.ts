import express from "express";
import { Pool } from "pg";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT ?? 3002);
const DATABASE_URL = process.env.DATABASE_URL!;
const JWT_SECRET = process.env.JWT_SECRET ?? "dev-secret";

const pool = new Pool({ connectionString: DATABASE_URL });

// health (two paths so it works with or without /notes prefix)
app.get("/health", (_req, res) => res.json({ service: "notes", ok: true }));
app.get("/notes/health", (_req, res) => res.json({ service: "notes", ok: true }));

function auth(req: any, res: any, next: any) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "unauthorized" });
  }
}

// list latest notes
app.get("/notes", auth, async (req: any, res) => {
  const { userId } = req.user;
  const q = await pool.query(
    "SELECT id, title, body, updated_at FROM notes WHERE user_id=$1 ORDER BY updated_at DESC LIMIT 50",
    [userId]
  );
  res.json(q.rows);
});

// create a note
app.post("/notes", auth, async (req: any, res) => {
  const { userId } = req.user;
  const { title, body } = req.body || {};
  const q = await pool.query(
    "INSERT INTO notes (user_id, title, body) VALUES ($1,$2,$3) RETURNING id",
    [userId, title, body]
  );
  res.status(201).json({ id: q.rows[0].id });
});

app.listen(PORT, () => console.log(`notes listening on ${PORT}`));

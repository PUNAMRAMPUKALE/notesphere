import express from "express";
import { Pool } from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT ?? 3001);
const DATABASE_URL = process.env.DATABASE_URL!;
const JWT_SECRET = process.env.JWT_SECRET ?? "dev-secret";

const pool = new Pool({ connectionString: DATABASE_URL });

app.get("/health", (_req, res) => res.json({ service: "auth", ok: true }));
app.get("/auth/health", (_req, res) => res.json({ service: "auth", ok: true })); // add this

app.post("/auth/signup", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email & password required" });
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    "INSERT INTO users (email, password_hash) VALUES ($1,$2) ON CONFLICT (email) DO NOTHING",
    [email, hash]
  );
  res.status(201).json({ email });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const q = await pool.query("SELECT id, password_hash FROM users WHERE email=$1", [email]);
  if (q.rowCount === 0) return res.status(401).json({ error: "invalid credentials" });
  const ok = await bcrypt.compare(password, q.rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });
  const token = jwt.sign({ userId: q.rows[0].id }, JWT_SECRET, { expiresIn: "30m" });
  res.json({ token });
});

app.listen(PORT, () => console.log(`auth listening on ${PORT}`));

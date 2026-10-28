const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("node:crypto");
const { execFile } = require("node:child_process");

const app = express();
app.use(helmet());
app.use(express.json({ limit: "100kb" }));
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
app.use("/login", rateLimit({ windowMs: 15 * 60 * 1000, limit: 5 }));

app.get("/items", requireAuth, async (req, res) => {
  const rows = await db.query("SELECT * FROM items WHERE owner_id = $1", [req.user.id]);
  res.json(rows);
});

app.post("/convert", requireAuth, (req, res) => {
  execFile("convert", ["--", "in.png", "out.png"], () => res.send("ok"));
});

app.post("/users", async (req, res) => {
  const { email, displayName } = req.body;
  const user = await User.create({ email: String(email), displayName: String(displayName), role: "user" });
  res.json({ id: user.id });
});

function render(el, comment) {
  el.textContent = comment.body;
}

const sessionToken = crypto.randomBytes(32).toString("base64url");
app.listen(3000);

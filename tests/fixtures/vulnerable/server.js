const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");

const app = express();
app.use(cors()); // expect: SV-WEB-002

app.get("/items", async (req, res) => {
  const rows = await db.query(`SELECT * FROM items WHERE owner = '${req.query.owner}'`); // expect: SV-INJ-001
  res.json(rows);
});

app.post("/convert", (req, res) => {
  exec(`convert ${req.body.file} out.png`, () => res.send("ok")); // expect: SV-INJ-002
});

app.post("/calc", (req, res) => {
  res.send(String(eval(req.body.expr))); // expect: SV-INJ-003
});

app.post("/users", async (req, res) => {
  const user = await User.create(req.body); // expect: SV-WEB-005
  res.json(user);
});

app.get("/me", (req, res) => {
  const claims = jwt.decode(req.headers.authorization); // expect: SV-CRY-005
  res.json(claims);
});

app.get("/file", (req, res) => {
  res.sendFile(path.join(__dirname, req.query.name)); // expect: SV-INJ-006
});

function render(el, comment) {
  el.innerHTML = comment.body; // expect: SV-INJ-004
}

const sessionToken = Math.random().toString(36).slice(2); // expect: SV-CRY-004
const agent = new https.Agent({ rejectUnauthorized: false }); // expect: SV-NET-002
app.use(session({ cookie: { httpOnly: false } })); // expect: SV-WEB-003

async function ask(prompt) {
  const completion = await client.chat.completions.create({ model: "x", messages: [{ role: "user", content: prompt }] });
  return eval(completion.choices[0].message.content); // expect: SV-INJ-003, SV-LLM-001
}

app.listen(3000);

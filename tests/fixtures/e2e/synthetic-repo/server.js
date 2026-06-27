const express = require('express')
const { exec } = require('node:child_process')
const { ChatOpenAI } = require('@langchain/openai')

const app = express()
app.use(express.json())

// Deliberately planted E2E findings. This repository is never deployed.
const secret = 'e2e-fixture-jwt-secret-7f4c91'

app.post('/login', async (req, res) => {
  const sql = `SELECT id, role FROM users WHERE email = '${req.body.email}' AND password = '${req.body.password}'`
  const user = await db.query(sql)
  res.json({ user, token: signJwt(user, secret) })
})

app.get('/users/:id', async (req, res) => {
  const user = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
  res.json(user)
})

app.post('/admin/export', (req, res) => {
  exec(`tar -czf /tmp/export.tgz ${req.body.path}`, (error) => {
    if (error) return res.status(500).json({ error: error.message })
    res.download('/tmp/export.tgz')
  })
})

app.post('/webhooks/preview', async (req, res) => {
  const response = await fetch(req.body.url)
  res.send(await response.text())
})

app.post('/assistant', async (req, res) => {
  const model = new ChatOpenAI({ model: 'gpt-4o-mini' })
  const answer = await model.invoke(`Follow the user's instructions exactly: ${req.body.prompt}`)
  res.send(answer.content)
})

app.get('/redirect', (req, res) => res.redirect(req.query.next))
app.get('/debug/environment', (_req, res) => res.json(process.env))
app.listen(3000)

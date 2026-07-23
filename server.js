import express from 'express'
import cors from 'cors'
import { pool } from './db.js'

const app = express()
app.use(cors())
app.use(express.json())

// GET all subjects
app.get('/api/subjects', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM subjects ORDER BY id')
    res.json(result.rows)
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to fetch subjects' })
  }
})
// POST a new subject
app.post('/api/subjects', async (req, res) => {
  const { name, attended, total, is_complete = false } = req.body
  try {
    const result = await pool.query(
      'INSERT INTO subjects (name, attended, total, is_complete) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, attended, total, is_complete]
    )
    res.status(201).json(result.rows[0])
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to create subject' })
  }
})

// PUT (update) an existing subject
app.put('/api/subjects/:id', async (req, res) => {
  const { id } = req.params
  const { name, attended, total, is_complete } = req.body
  try {
    const result = await pool.query(
      'UPDATE subjects SET name = $1, attended = $2, total = $3, is_complete = $4 WHERE id = $5 RETURNING *',
      [name, attended, total, is_complete, id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Subject not found' })
    }
    res.json(result.rows[0])
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to update subject' })
  }
})

// DELETE a subject
app.delete('/api/subjects/:id', async (req, res) => {
  const { id } = req.params
  try {
    const result = await pool.query('DELETE FROM subjects WHERE id = $1 RETURNING *', [id])
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Subject not found' })
    }
    res.json({ message: 'Subject deleted' })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to delete subject' })
  }
})
const PORT = 3001
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})
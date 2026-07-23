import express from 'express'
import cors from 'cors'
import { pool } from './db.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' })
  }

  const token = authHeader.split(' ')[1]

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.studentId = decoded.studentId
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}

const app = express()
app.use(cors())
app.use(express.json())

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password } = req.body

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are all required' })
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10)

    const result = await pool.query(
      'INSERT INTO students (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, hashedPassword]
    )

    const student = result.rows[0]
    const token = jwt.sign({ studentId: student.id }, process.env.JWT_SECRET, { expiresIn: '7d' })

    res.status(201).json({ student, token })
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'An account with this email already exists' })
    }
    console.error(err)
    res.status(500).json({ error: 'Failed to create account' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' })
  }

  try {
    const result = await pool.query('SELECT * FROM students WHERE email = $1', [email])

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' })
    }

    const student = result.rows[0]
    const passwordMatches = await bcrypt.compare(password, student.password)

    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid email or password' })
    }

    const token = jwt.sign({ studentId: student.id }, process.env.JWT_SECRET, { expiresIn: '7d' })

    res.json({
      student: { id: student.id, name: student.name, email: student.email },
      token,
    })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to log in' })
  }
})

// GET all subjects — only the logged-in student's own
app.get('/api/subjects', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM subjects WHERE student_id = $1 ORDER BY id',
      [req.studentId]
    )
    res.json(result.rows)
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to fetch subjects' })
  }
})

// POST a new subject — tied to the logged-in student
app.post('/api/subjects', requireAuth, async (req, res) => {
  const { name, attended, total, is_complete = false } = req.body
  try {
    const result = await pool.query(
      'INSERT INTO subjects (student_id, name, attended, total, is_complete) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.studentId, name, attended, total, is_complete]
    )
    res.status(201).json(result.rows[0])
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to create subject' })
  }
})

// PUT (update) — only if it belongs to the logged-in student
app.put('/api/subjects/:id', requireAuth, async (req, res) => {
  const { id } = req.params
  const { name, attended, total, is_complete } = req.body
  try {
    const result = await pool.query(
      'UPDATE subjects SET name = $1, attended = $2, total = $3, is_complete = $4 WHERE id = $5 AND student_id = $6 RETURNING *',
      [name, attended, total, is_complete, id, req.studentId]
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

// DELETE — only if it belongs to the logged-in student
app.delete('/api/subjects/:id', requireAuth, async (req, res) => {
  const { id } = req.params
  try {
    const result = await pool.query(
      'DELETE FROM subjects WHERE id = $1 AND student_id = $2 RETURNING *',
      [id, req.studentId]
    )
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
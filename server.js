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

// ============ AUTH ROUTES ============

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

// ============ SUBJECT ROUTES ============

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

app.post('/api/subjects', requireAuth, async (req, res) => {
  const { name, required_percentage } = req.body

  if (!name || name.trim() === '') {
    return res.status(400).json({ error: 'Subject name is required' })
  }
  if (
    required_percentage === undefined ||
    required_percentage < 0 ||
    required_percentage > 100
  ) {
    return res.status(400).json({ error: 'Required percentage must be between 0 and 100' })
  }

  try {
    const result = await pool.query(
      'INSERT INTO subjects (student_id, name, required_percentage) VALUES ($1, $2, $3) RETURNING *',
      [req.studentId, name, required_percentage]
    )
    res.status(201).json(result.rows[0])
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to create subject' })
  }
})

app.put('/api/subjects/:id', requireAuth, async (req, res) => {
  const { id } = req.params
  const { name, required_percentage, is_semester_complete } = req.body
  try {
    const result = await pool.query(
      `UPDATE subjects
       SET name = COALESCE($1, name),
           required_percentage = COALESCE($2, required_percentage),
           is_semester_complete = COALESCE($3, is_semester_complete)
       WHERE id = $4 AND student_id = $5
       RETURNING *`,
      [name, required_percentage, is_semester_complete, id, req.studentId]
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

// ============ ATTENDANCE LOG ROUTES ============

// Log or update a day's status
app.post('/api/subjects/:id/log', requireAuth, async (req, res) => {
  const { id } = req.params
  const { log_date, status } = req.body

  if (!log_date || !['present', 'absent', 'no_class'].includes(status)) {
    return res.status(400).json({ error: 'A valid date and status are required' })
  }

  try {
    const subjectCheck = await pool.query(
      'SELECT * FROM subjects WHERE id = $1 AND student_id = $2',
      [id, req.studentId]
    )
    if (subjectCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Subject not found' })
    }
    if (subjectCheck.rows[0].is_semester_complete) {
      return res.status(400).json({ error: 'Semester is marked complete — reopen it before logging' })
    }

    const result = await pool.query(
      `INSERT INTO attendance_log (subject_id, log_date, status)
       VALUES ($1, $2, $3)
       ON CONFLICT (subject_id, log_date)
       DO UPDATE SET status = EXCLUDED.status
       RETURNING *`,
      [id, log_date, status]
    )
    res.status(201).json(result.rows[0])
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to log attendance' })
  }
})

// Get full attendance history for a subject
app.get('/api/subjects/:id/log', requireAuth, async (req, res) => {
  const { id } = req.params
  try {
    const subjectCheck = await pool.query(
      'SELECT * FROM subjects WHERE id = $1 AND student_id = $2',
      [id, req.studentId]
    )
    if (subjectCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Subject not found' })
    }

    const result = await pool.query(
      'SELECT * FROM attendance_log WHERE subject_id = $1 ORDER BY log_date ASC',
      [id]
    )
    res.json(result.rows)
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to fetch attendance history' })
  }
})

// Edit a specific past entry
app.put('/api/subjects/:id/log/:logId', requireAuth, async (req, res) => {
  const { id, logId } = req.params
  const { status } = req.body

  if (!['present', 'absent', 'no_class'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' })
  }

  try {
    const result = await pool.query(
      `UPDATE attendance_log SET status = $1
       WHERE id = $2 AND subject_id = $3
       AND subject_id IN (SELECT id FROM subjects WHERE student_id = $4)
       RETURNING *`,
      [status, logId, id, req.studentId]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Entry not found' })
    }
    res.json(result.rows[0])
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to update entry' })
  }
})

// Delete a specific past entry
app.delete('/api/subjects/:id/log/:logId', requireAuth, async (req, res) => {
  const { id, logId } = req.params
  try {
    const result = await pool.query(
      `DELETE FROM attendance_log
       WHERE id = $1 AND subject_id = $2
       AND subject_id IN (SELECT id FROM subjects WHERE student_id = $3)
       RETURNING *`,
      [logId, id, req.studentId]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Entry not found' })
    }
    res.json({ message: 'Entry deleted' })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to delete entry' })
  }
})

// ============ CALCULATION / REPORT ROUTE ============

app.get('/api/subjects/:id/report', requireAuth, async (req, res) => {
  const { id } = req.params

  try {
    const subjectResult = await pool.query(
      'SELECT * FROM subjects WHERE id = $1 AND student_id = $2',
      [id, req.studentId]
    )
    if (subjectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Subject not found' })
    }
    const subject = subjectResult.rows[0]

    const logResult = await pool.query(
      'SELECT status FROM attendance_log WHERE subject_id = $1',
      [id]
    )
    const entries = logResult.rows

    const present = entries.filter((e) => e.status === 'present').length
    const absent = entries.filter((e) => e.status === 'absent').length
    const total = present + absent // 'no_class' entries never count

    const currentPercent = total === 0 ? null : (present / total) * 100
    const requiredPercent = subject.required_percentage

    // If semester is complete, this is a final, locked report — no simulation needed
    if (subject.is_semester_complete) {
      return res.json({
        subject: subject.name,
        requiredPercent,
        present,
        absent,
        total,
        currentPercent,
        isComplete: true,
        recommendation: null,
      })
    }

    // No classes logged yet at all
    if (total === 0) {
      return res.json({
        subject: subject.name,
        requiredPercent,
        present,
        absent,
        total,
        currentPercent: null,
        isComplete: false,
        recommendation: 'No attendance available. Waiting for the first class.',
      })
    }

    // Simulate today's class both ways
    const ifPresentPercent = (present + 1) / (total + 1) * 100
    const ifAbsentPercent = present / (total + 1) * 100

    const canBunk = ifAbsentPercent >= requiredPercent

    let status
    if (currentPercent === 100) status = 'excellent'
    else if (currentPercent >= requiredPercent && canBunk) status = 'safe'
    else if (currentPercent >= requiredPercent && !canBunk) status = 'borderline'
    else status = 'danger'

    const recommendation = canBunk
      ? "You may bunk today's class."
      : "Attend today's class."

    res.json({
      subject: subject.name,
      requiredPercent,
      present,
      absent,
      total,
      currentPercent,
      ifPresentPercent,
      ifAbsentPercent,
      status,
      recommendation,
      isComplete: false,
    })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed to generate report' })
  }
})

const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
/* server.js */
require('dotenv').config(); // load .env locally; on Render it uses dashboard vars

const express = require('express');
const multer = require('multer');
const fs = require('fs');
const cors = require('cors');
const PDFDocument = require('pdfkit');
const path = require('path');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// === Static files for dashboard & uploads ===
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/admin', express.static(path.join(__dirname, 'public'))); // serves admin.html

// === File uploads (client optional file) ===
const upload = multer({ dest: 'uploads/' });

// === Email transporter (set creds in environment variables) ===
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,   // e.g. youremail@gmail.com
    pass: process.env.EMAIL_PASS    // Gmail App Password
  }
});

// === JWT Auth helpers ===
function makeToken() {
  return jwt.sign({ role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '2h' });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') throw new Error('not admin');
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}

// === Admin Login (POST /admin/api/login) ===
// Preferred: set ADMIN_HASH (bcrypt hash). Fallback: ADMIN_PASSWORD (plain) if hash not set.
app.post('/admin/api/login', (req, res) => {
  const { password } = req.body;
  const adminHash = process.env.ADMIN_HASH || '';
  const adminPlain = process.env.ADMIN_PASSWORD || '';

  let ok = false;
  if (adminHash) {
    ok = bcrypt.compareSync(password, adminHash);
  } else if (adminPlain) {
    ok = password === adminPlain;
  }

  if (!ok) return res.status(401).json({ message: 'Invalid password' });
  const token = makeToken();
  return res.json({ token });
});

// === Client order submission (public) ===
app.post('/submit-order', upload.single('fileupload'), async (req, res) => {
  const { fullname, email, category, requirements } = req.body;
  const file = req.file ? req.file.filename : '';
  const date = new Date().toISOString();
  const line = `"${fullname}","${email}","${category}","${requirements}","${file}","${date}"\n`;

  // Ensure file exists then append
  if (!fs.existsSync('orders.csv')) fs.writeFileSync('orders.csv', '');
  fs.appendFileSync('orders.csv', line);

  // Notify admin
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: process.env.EMAIL_USER,
        subject: 'New Order Received',
        html: `<h3>New Order</h3>
               <p><b>Name:</b> ${fullname}</p>
               <p><b>Email:</b> ${email}</p>
               <p><b>Category:</b> ${category}</p>
               <p><b>Requirements:</b> ${requirements}</p>
               <p><b>File:</b> ${file || 'No file'}</p>
               <p><b>Date:</b> ${date}</p>`
      });
    } catch (err) {
      console.log('Admin email error:', err.message);
    }

    // Auto reply to client
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Order is Received',
        html: `<h3>Hi ${fullname},</h3>
               <p>Thank you for your order. We have received it and will notify you once it is processed.</p>
               <ul>
                 <li>Category: ${category}</li>
                 <li>Requirements: ${requirements}</li>
                 <li>Date: ${date}</li>
               </ul>
               <p>Best regards,<br>Admin</p>`
      });
    } catch (err) {
      console.log('Client email error:', err.message);
    }
  }

  res.send('Thank you! Your order has been received.');
});

// === Admin APIs (all protected by JWT) ===
app.get('/admin/api/orders-data', authMiddleware, (req, res) => {
  if (!fs.existsSync('orders.csv')) return res.json([]);
  const data = fs.readFileSync('orders.csv', 'utf8')
    .split('\n').filter(l => l.trim() !== '');
  const orders = data.map((line, i) => {
    const parts = line.split(/","|^"|"$/g).filter(p => p);
    return {
      index: i,
      fullname: parts[0],
      email: parts[1],
      category: parts[2],
      requirements: parts[3],
      file: parts[4],
      date: parts[5]
    };
  });
  res.json(orders);
});

app.delete('/admin/api/order/:index', authMiddleware, (req, res) => {
  const idx = parseInt(req.params.index, 10);
  if (!fs.existsSync('orders.csv')) return res.status(400).send('No orders');
  const lines = fs.readFileSync('orders.csv', 'utf8')
    .split('\n').filter(l => l.trim() !== '');
  if (idx < 0 || idx >= lines.length) return res.status(400).send('Invalid index');
  lines.splice(idx, 1);
  fs.writeFileSync('orders.csv', lines.join('\n') + (lines.length ? '\n' : ''));
  res.send('Order deleted');
});

app.get('/admin/api/orders/pdf', authMiddleware, (req, res) => {
  if (!fs.existsSync('orders.csv')) return res.status(404).send('No orders');
  const data = fs.readFileSync('orders.csv', 'utf8')
    .split('\n').filter(l => l.trim() !== '');

  const doc = new PDFDocument();
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename=orders.pdf');
  doc.pipe(res);
  doc.fontSize(18).text('Orders List', { align: 'center' }).moveDown();

  data.forEach((line, i) => {
    const parts = line.split(/","|^"|"$/g).filter(p => p);
    doc.fontSize(12).text(
      `${i + 1}. Name: ${parts[0]}, Email: ${parts[1]}, Category: ${parts[2]}, Requirements: ${parts[3]}, File: ${parts[4]}, Date: ${parts[5]}`
    );
    doc.moveDown(0.5);
  });
  doc.end();
});

app.post('/admin/api/email-client', authMiddleware, async (req, res) => {
  const { email, subject, message } = req.body;
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    return res.status(500).send('Email not configured');
  }
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject,
      html: message
    });
    res.send('Email sent successfully');
  } catch (err) {
    res.status(500).send('Error sending email: ' + err.message);
  }
});

app.post('/admin/api/email-all', authMiddleware, async (req, res) => {
  const { subject, message } = req.body;
  if (!fs.existsSync('orders.csv')) return res.status(400).send('No clients');
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    return res.status(500).send('Email not configured');
  }
  const data = fs.readFileSync('orders.csv', 'utf8').split('\n').filter(l => l.trim() !== '');
  const emails = data.map(line => line.split(/","|^"|"$/g).filter(p => p)[1]);

  try {
    for (const e of emails) {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: e,
        subject,
        html: message
      });
    }
    res.send('Emails sent to all clients');
  } catch (err) {
    res.status(500).send('Error sending emails: ' + err.message);
  }
});

// === Serve the dashboard HTML at /admin (handled by static) ===
// Visiting /admin will load public/admin.html

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));

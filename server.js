/* server.js */
require('dotenv').config();

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
app.use('/admin', express.static(path.join(__dirname, 'public')));

// === File uploads ===
const upload = multer({ dest: 'uploads/' });

// === Email transporter ===
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
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

// === Admin Login ===
app.post('/admin/api/login', (req, res) => {
  const { password } = req.body;
  const adminHash = process.env.ADMIN_HASH || '';
  const adminPlain = process.env.ADMIN_PASSWORD || '';
  let ok = false;
  if (adminHash) ok = bcrypt.compareSync(password, adminHash);
  else if (adminPlain) ok = password === adminPlain;
  if (!ok) return res.status(401).json({ message: 'Invalid password' });
  const token = makeToken();
  return res.json({ token });
});

// === VISITOR TRACKING ===
const visitorFile = path.join(__dirname, 'visitors.json');

app.post('/log-visit', (req, res) => {
  let visitors = [];
  if (fs.existsSync(visitorFile)) visitors = JSON.parse(fs.readFileSync(visitorFile));
  visitors.push({ time: new Date().toISOString(), page: req.body.page || 'unknown', ip: req.ip });
  fs.writeFileSync(visitorFile, JSON.stringify(visitors, null, 2));
  res.sendStatus(200);
});

app.get('/admin/api/get-visits', authMiddleware, (req, res) => {
  let visitors = [];
  if (fs.existsSync(visitorFile)) visitors = JSON.parse(fs.readFileSync(visitorFile));
  res.json(visitors);
});

// === LOCK / UNLOCK ORDERS ===
const lockFile = path.join(__dirname, 'orders_locked.json');
function isOrdersLocked() {
  if (!fs.existsSync(lockFile)) return false;
  const status = JSON.parse(fs.readFileSync(lockFile));
  return status.locked;
}

app.post('/admin/api/lock-orders', authMiddleware, (req, res) => {
  fs.writeFileSync(lockFile, JSON.stringify({ locked: true }));
  res.send({ locked: true });
});

app.post('/admin/api/unlock-orders', authMiddleware, (req, res) => {
  fs.writeFileSync(lockFile, JSON.stringify({ locked: false }));
  res.send({ locked: false });
});

// === Client order submission ===
app.post('/submit-order', upload.single('fileupload'), async (req, res) => {
  if (isOrdersLocked()) return res.status(403).send('Orders are currently locked');

  const { fullname, email, category, requirements } = req.body;
  const file = req.file ? req.file.filename : '';
  const date = new Date().toISOString();
  const line = `"${fullname}","${email}","${category}","${requirements}","${file}","${date}"\n`;

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
               <p><b>Date:</b> ${new Date(date).toLocaleString()}</p>`
      });
    } catch (err) { console.log('Admin email error:', err.message); }

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Order is Received',
        html: `<h3>Hi ${fullname},</h3>
               <p>Thank you for your order. We have received it.</p>
               <ul>
                 <li>Category: ${category}</li>
                 <li>Requirements: ${requirements}</li>
                 <li>Date: ${new Date(date).toLocaleString()}</li>
               </ul>
               <p>Best regards,<br>Admin</p>`
      });
    } catch (err) { console.log('Client email error:', err.message); }
  }

  res.send('Thank you! Your order has been received.');
});

// === Admin APIs ===
app.get('/admin/api/orders-data', authMiddleware, (req, res) => {
  if (!fs.existsSync('orders.csv')) return res.json([]);
  const data = fs.readFileSync('orders.csv', 'utf8').split('\n').filter(l => l.trim() !== '');
  const orders = data.map((line, i) => {
    const parts = line.split(/","|^"|"$/g).filter(p => p);
    return { index: i, fullname: parts[0], email: parts[1], category: parts[2], requirements: parts[3], file: parts[4], date: parts[5] };
  });
  res.json(orders);
});

app.delete('/admin/api/order/:index', authMiddleware, (req, res) => {
  const idx = parseInt(req.params.index, 10);
  if (!fs.existsSync('orders.csv')) return res.status(400).send('No orders');
  const lines = fs.readFileSync('orders.csv', 'utf8').split('\n').filter(l => l.trim() !== '');
  if (idx < 0 || idx >= lines.length) return res.status(400).send('Invalid index');
  lines.splice(idx, 1);
  fs.writeFileSync('orders.csv', lines.join('\n') + (lines.length ? '\n' : ''));
  res.send('Order deleted');
});

// === Reject Order with Email ===
app.post('/admin/api/reject-order/:index', authMiddleware, async (req, res) => {
  const idx = parseInt(req.params.index, 10);
  if (!fs.existsSync('orders.csv')) return res.status(400).send('No orders');
  const lines = fs.readFileSync('orders.csv', 'utf8').split('\n').filter(l => l.trim() !== '');
  if (idx < 0 || idx >= lines.length) return res.status(400).send('Invalid index');

  const parts = lines[idx].split(/","|^"|"$/g).filter(p => p);
  const email = parts[1], fullname = parts[0];

  lines.splice(idx, 1);
  fs.writeFileSync('orders.csv', lines.join('\n') + (lines.length ? '\n' : ''));

  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Your Order Was Rejected',
        html: `<h3>Hi ${fullname},</h3>
               <p>Unfortunately, your order has been rejected by the admin.</p>
               <p>If you have questions, please contact support.</p>`
      });
    } catch(err){ console.log('Client reject email error:', err.message); }
  }

  res.send('Order rejected and client notified');
});

// === Send Email Single / All Clients ===
app.post('/admin/api/email-client', authMiddleware, async (req, res) => {
  const { email, subject, message } = req.body;
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) return res.status(500).send('Email not configured');
  try { await transporter.sendMail({ from: process.env.EMAIL_USER, to: email, subject, html: message }); res.send('Email sent successfully'); }
  catch (err) { res.status(500).send('Error sending email: ' + err.message); }
});

app.post('/admin/api/email-all', authMiddleware, async (req
// === GET VISITOR STATS ===
app.get('/admin/api/visitors', authMiddleware, (req, res) => {
  let visitors = [];
  if (fs.existsSync(visitorFile)) {
    visitors = JSON.parse(fs.readFileSync(visitorFile));
  }
  res.json(visitors);
});

// === DEFAULT ROUTE ===
app.get('/', (req, res) => {
  res.send('Welcome to GigiCraft Hub Backend');
});

// === START SERVER ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));

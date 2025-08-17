const express = require('express');
const multer = require('multer');
const fs = require('fs');
const cors = require('cors');
const basicAuth = require('express-basic-auth');
const PDFDocument = require('pdfkit');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Upload folder
const upload = multer({ dest: 'uploads/' });

// Admin login
app.use('/admin', basicAuth({
  users: { 'admin': 'password123' },
  challenge: true
}));

// Serve admin dashboard
app.get('/admin', (req,res)=>{
  res.sendFile(path.join(__dirname,'public','admin.html'));
});

// Email transporter (Gmail)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'youremail@gmail.com',      // <== your email
    pass: 'your_app_password_here'    // <== Gmail App password
  }
});

// Submit order endpoint
app.post('/submit-order', upload.single('fileupload'), async (req, res) => {
  const { fullname, email, category, requirements } = req.body;
  const file = req.file ? req.file.filename : '';
  const date = new Date().toISOString();
  const line = `"${fullname}","${email}","${category}","${requirements}","${file}","${date}"\n`;
  fs.appendFileSync('orders.csv', line);

  // Email to admin
  try {
    await transporter.sendMail({
      from: 'youremail@gmail.com',
      to: 'youremail@gmail.com',
      subject: 'New Order Received',
      html: `<h3>New Order</h3>
             <p><b>Name:</b> ${fullname}</p>
             <p><b>Email:</b> ${email}</p>
             <p><b>Category:</b> ${category}</p>
             <p><b>Requirements:</b> ${requirements}</p>
             <p><b>File:</b> ${file ? file : 'No file'}</p>
             <p><b>Date:</b> ${date}</p>`
    });
  } catch(err){ console.log('Admin email error:', err); }

  // Email to client
  try {
    await transporter.sendMail({
      from: 'youremail@gmail.com',
      to: email,
      subject: 'Your Order is Received',
      html: `<h3>Hi ${fullname},</h3>
             <p>Thank you for your order. We have received it successfully and will notify you once it is processed.</p>
             <p>Order Details:</p>
             <ul>
               <li>Category: ${category}</li>
               <li>Requirements: ${requirements}</li>
               <li>Date: ${date}</li>
             </ul>
             <p>Best regards,<br>Admin</p>`
    });
  } catch(err){ console.log('Client email error:', err); }

  res.send('Thank you! Your order has been received.');
});

// Admin: list orders
app.get('/admin/orders-data', (req,res)=>{
  if(!fs.existsSync('orders.csv')) return res.json([]);
  const data = fs.readFileSync('orders.csv','utf8').split('\n').filter(l=>l.trim()!=='');
  const orders = data.map((line,i)=>{
    const parts = line.split(/","|^"|"$/g).filter(p=>p);
    return { index:i, fullname:parts[0], email:parts[1], category:parts[2], requirements:parts[3], file:parts[4], date:parts[5] };
  });
  res.json(orders);
});

// Admin: delete order
app.delete('/admin/order/:index', (req,res)=>{
  const idx = parseInt(req.params.index);
  const lines = fs.readFileSync('orders.csv','utf8').split('\n').filter(l=>l.trim()!=='');
  if(idx<0 || idx>=lines.length) return res.status(400).send('Invalid index');
  lines.splice(idx,1);
  fs.writeFileSync('orders.csv', lines.join('\n')+'\n');
  res.send('Order deleted');
});

// Admin: download orders as PDF
app.get('/admin/orders/pdf', (req,res)=>{
  if(!fs.existsSync('orders.csv')) return res.status(404).send('No orders');
  const data = fs.readFileSync('orders.csv','utf8').split('\n').filter(l=>l.trim()!=='');
  const doc = new PDFDocument();
  res.setHeader('Content-Type','application/pdf');
  res.setHeader('Content-Disposition','attachment; filename=orders.pdf');
  doc.pipe(res);
  doc.fontSize(18).text('Orders List', {align:'center'}).moveDown();
  data.forEach((line,i)=>{
    const parts = line.split(/","|^"|"$/g).filter(p=>p);
    doc.fontSize(12).text(`${i+1}. Name: ${parts[0]}, Email: ${parts[1]}, Category: ${parts[2]}, Requirements: ${parts[3]}, File: ${parts[4]}, Date: ${parts[5]}`);
    doc.moveDown(0.5);
  });
  doc.end();
});

// Admin: send email to one client
app.post('/admin/email-client', async (req,res)=>{
  const { email, subject, message } = req.body;
  try{
    await transporter.sendMail({
      from: 'youremail@gmail.com',
      to: email,
      subject: subject,
      html: message
    });
    res.send('Email sent successfully');
  } catch(err){
    res.status(500).send('Error sending email: '+err);
  }
});

// Admin: send email to all clients
app.post('/admin/email-all', async (req,res)=>{
  const { subject, message } = req.body;
  if(!fs.existsSync('orders.csv')) return res.status(400).send('No clients');
  const data = fs.readFileSync('orders.csv','utf8').split('\n').filter(l=>l.trim()!=='');
  const emails = data.map(line=>line.split(/","|^"|"$/g).filter(p=>p)[1]);
  try{
    for(const e of emails){
      await transporter.sendMail({
        from: 'youremail@gmail.com',
        to: e,
        subject: subject,
        html: message
      });
    }
    res.send('Emails sent to all clients');
  } catch(err){
    res.status(500).send('Error sending emails: '+err);
  }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname,'uploads')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`Backend running on port ${PORT}`));

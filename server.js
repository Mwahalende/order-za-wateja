require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const fs = require('fs');
const cron = require('node-cron');
const cloudinary = require('cloudinary').v2;
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("mongo connected"))
  .catch((err) => console.log("mongo error", err));

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const Admin = mongoose.model('Admin', new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  contact: String
}));

const Customer = mongoose.model('Customer', new mongoose.Schema({
  name: String,
  email: String,
  contact: String,
  password: String
}));

const Product = mongoose.model('Product', new mongoose.Schema({
  name: String,
  amount: Number,
  description: String,
  url: String,
  createdAt: { type: Date, default: Date.now }
}));

const Order = mongoose.model('Order', new mongoose.Schema({
  name: String,
  product: String,
  amount: Number,
  quantity: Number,
  email: String,
  contact: String,
  status: { type: String, default: 'Pending' },
  createdAt: { type: Date, default: Date.now }
}));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function sendEmail(to, subject, html) {
  transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject,
    html
  }, err => {
    if (err) console.log('Email error:', err.message);
  });
}

// === ADMIN REGISTER ===
app.post('/adminregister', async (req, res) => {
  try {
    const { name, email, password, contact } = req.body;
    const exists = await Admin.findOne({ email });
    if (exists) return res.status(400).json({ error: 'Admin already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({ name, email, password: hashedPassword, contact });
    await newAdmin.save();

    req.session.admin = { name: newAdmin.name, email: newAdmin.email };
    return res.redirect('/admindashboard.html');
  } catch (err) {
    console.error('Admin registration failed:', err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// === ADMIN LOGIN ===
app.post('/adminlogin', async (req, res) => {
  const { email, password } = req.body;
  const admin = await Admin.findOne({ email });
  if (!admin) return res.send('Invalid credentials');

  const isMatch = await bcrypt.compare(password, admin.password);
  if (!isMatch) return res.send('Invalid credentials');

  req.session.admin = { email: admin.email, name: admin.name, contact: admin.contact };
  res.redirect('/admindashboard.html');
});

app.get('/getadmin', (req, res) => {
  if (!req.session.admin) return res.status(401).json({ error: 'Unauthorized' });
  res.json(req.session.admin);
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/adminlogin.html'));
});

app.get('/admindashboard.html', (req, res, next) => {
  if (!req.session.admin) return res.redirect('/adminlogin.html');
  next();
}, express.static(path.join(__dirname, 'public', 'admindashboard.html')));

// === CUSTOMER REGISTER ===
app.post('/register', async (req, res) => {
  const { name, email, contact, password } = req.body;
  const exist = await Customer.findOne({ email });
  if (exist) return res.json({ success: false, message: 'Customer already exists' });
  await Customer.create({ name, email, contact, password });
  sendEmail(email, 'Welcome to our Store', `Hello ${name}, welcome to our website!`);
  res.json({ success: true });
});

// === CUSTOMER LOGIN ===
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await Customer.findOne({ email, password });
  if (!user) return res.json({ success: false, message: 'Invalid credentials' });
  res.json({ success: true, user: { name: user.name, email: user.email, contact: user.contact } });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

app.post('/uploadproduct', upload.single('media'), async (req, res) => {
  try {
    const { name, amount, description } = req.body;
    const result = await cloudinary.uploader.upload(req.file.path, { resource_type: "auto" });
    await Product.create({ name, amount, description, url: result.secure_url });

    const customers = await Customer.find();
    customers.forEach(c => {
      sendEmail(c.email, 'New Product Available', `
        Hello, check out our new product: ${name} for ${amount} TZS.
        <br><img src="${result.secure_url}" style="width:200px"/>
        <br><a href="http://your-website.com">Visit Us</a>
      `);
    });
    fs.unlinkSync(req.file.path);
    res.redirect('/admindashboard.html');
  } catch (err) {
    console.error(err);
    res.status(500).send('Upload failed');
  }
});

app.get('/products', async (req, res) => {
  try {
    const data = await Product.find();
    res.json(data);
  } catch (err) {
    res.status(500).send('Failed to load products');
  }
});

app.get('/orders', async (req, res) => {
  try {
    const data = await Order.find();
    res.json(data);
  } catch (err) {
    res.status(500).send('Failed to load orders');
  }
});

app.post('/placeorder', async (req, res) => {
  try {
    const { product, amount, email, contact, quantity } = req.body;
    const customer = await Customer.findOne({ email });
    const name = customer ? customer.name : '';
    await Order.create({ name, product, amount, quantity, email, contact });
    sendEmail(email, 'Order Confirmation', `You have ordered <b>${quantity}</b> x <b>${product}</b> for a total of <b>${amount} TZS</b>`);
    res.json({ success: true, message: 'Order placed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Order failed' });
  }
});

app.post('/updateadmin', async (req, res) => {
  const { name, email, contact } = req.body;
  try {
    const admin = await Admin.findOneAndUpdate({ email }, { name, contact }, { new: true });
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    req.session.admin = { email: admin.email, name: admin.name, contact: admin.contact };
    res.json(admin);
  } catch {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.post('/updateproduct', async (req, res) => {
  const { id, name, amount, description } = req.body;
  try {
    const product = await Product.findByIdAndUpdate(id, { name, amount, description }, { new: true });
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Update failed' });
  }
});

app.delete('/deleteproduct/:id', async (req, res) => {
  try {
    const prod = await Product.findById(req.params.id);
    if (!prod) return res.status(404).json({ error: 'Product not found' });

    if (prod.url) {
      const urlParts = prod.url.split('/');
      const fileName = urlParts[urlParts.length - 1];
      const publicId = fileName.substring(0, fileName.lastIndexOf('.'));

      const ext = fileName.split('.').pop().toLowerCase();
      const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff'];
      const videoExts = ['mp4', 'webm', 'ogg', 'avi', 'mov', 'flv', 'mkv'];

      let resourceType = 'image';
      if (videoExts.includes(ext)) {
        resourceType = 'video';
      } else if (!imageExts.includes(ext)) {
        resourceType = 'raw';
      }

      await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
    }

    await Order.deleteMany({ product: prod.name });
    await Product.findByIdAndDelete(req.params.id);

    res.json({ success: true, message: 'Product and related orders deleted.' });
  } catch (err) {
    console.error('Delete product error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.post('/approveorder/:id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (order) {
      order.status = 'Approved';
      await order.save();
      sendEmail(order.email, 'Order Approved', `Your order for ${order.product} has been approved!`);
    }
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Approval failed' });
  }
});

app.delete('/deleteorder/:id', async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Delete failed' });
  }
});

cron.schedule('0 8,18 * * *', async () => {
  try {
    const users = await Customer.find();
    users.forEach(u => {
      sendEmail(u.email, 'Visit Us Today!', `
        Good day ${u.name}, check our latest offers and deals!
        <br><a href="http://your-website.com">Visit Our Shop</a>
      `);
    });
    console.log('Daily marketing emails sent');
  } catch (err) {
    console.error('Error sending marketing emails:', err);
  }
});

app.post('/admin-forgot-password', async (req, res) => {
  const { email } = req.body;
  const admin = await Admin.findOne({ email });
  if (!admin) return res.json({ success: false, message: 'Email not found.' });

  const newPassword = Math.random().toString(36).slice(-8);
  const hashed = await bcrypt.hash(newPassword, 10);
  admin.password = hashed;
  await admin.save();

  sendEmail(email, 'Admin Password Reset', `Your new admin password is: <b>${newPassword}</b>`);
  res.json({ success: true, message: 'A new password has been sent to your email.' });
});

app.get('/api/users', async (req, res) => {
  try {
    const admins = await Admin.find();
    const customers = await Customer.find();
    res.json({ admins, customers });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});
app.delete('/api/admins/:id', async (req, res) => {
  try {
    await Admin.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete admin' });
  }
});

app.delete('/api/customers/:id', async (req, res) => {
  try {
    await Customer.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete customer' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

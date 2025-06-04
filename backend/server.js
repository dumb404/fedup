const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcrypt');
require('dotenv').config();

const User = require('./models/user');
const Admin = require('./models/admin');

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Multer for image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Register User
app.post('/register-user', async (req, res) => {
  console.log('POST /register-user', req.body);
  try {
    const { password, email, username, first_name, last_name, country } = req.body;
    if (!password || !email || !username || !first_name || !last_name || !country) {
      return res.status(400).send('Missing required fields');
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send('Email already registered');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ ...req.body, password: hashedPassword });
    await newUser.save();
    res.send('User Registered Successfully');
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).send(`Error registering user: ${err.message}`);
  }
});

// Register Admin
app.post('/register-admin', async (req, res) => {
  console.log('POST /register-admin', req.body);
  try {
    const { password, email, username, admin_type, country, thana } = req.body;
    if (!password || !email || !username || !admin_type || !country || !thana) {
      return res.status(400).send('Missing required fields');
    }
    const existingAdmin = await Admin.findOne({ email, admin_type });
    if (existingAdmin) {
      return res.status(400).send('Email already registered for this admin type');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({ ...req.body, password: hashedPassword });
    await newAdmin.save();
    res.send('Admin Registered Successfully');
  } catch (err) {
    console.error('Error registering admin:', err);
    res.status(500).send(`Error registering admin: ${err.message}`);
  }
});

// Login User
app.post('/login-user', async (req, res) => {
  console.log('POST /login-user', req.body);
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).send('Invalid email or password');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      res.send('Login Successful');
    } else {
      res.status(401).send('Invalid email or password');
    }
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).send('Error during login');
  }
});

// Login Admin
app.post('/login-admin', async (req, res) => {
  console.log('POST /login-admin', req.body);
  try {
    const { email, password, admin_type } = req.body;
    const admin = await Admin.findOne({ email, admin_type });
    if (!admin) {
      return res.status(401).send('Invalid email, password, or admin type');
    }
    const isMatch = await bcrypt.compare(password, admin.password);
    if (isMatch) {
      res.send('Login Successful');
    } else {
      res.status(401).send('Invalid email, password, or admin type');
    }
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).send('Error during login');
  }
});

// Get User Data
app.post('/user-data', async (req, res) => {
  console.log('POST /user-data', req.body);
  try {
    const { email } = req.body;
    const user = await User.findOne({ email }).select('-password');
    if (user) {
      res.json(user);
    } else {
      res.status(404).send('User not found');
    }
  } catch (err) {
    console.error('Error fetching user data:', err);
    res.status(500).send('Error fetching user data');
  }
});

// Get Admin Data
app.post('/admin-data', async (req, res) => {
  console.log('POST /admin-data', req.body);
  try {
    const { email, admin_type } = req.body;
    const admin = await Admin.findOne({ email, admin_type }).select('-password');
    if (admin) {
      res.json(admin);
    } else {
      res.status(404).send('Admin not found');
    }
  } catch (err) {
    console.error('Error fetching admin data:', err);
    res.status(500).send('Error fetching admin data');
  }
});

// Change Password User
app.post('/change-password-user', async (req, res) => {
  console.log('POST /change-password-user', req.body);
  try {
    const { email, newPassword } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const user = await User.findOneAndUpdate(
      { email },
      { password: hashedPassword },
      { new: true }
    );
    if (user) {
      res.send('Password changed successfully');
    } else {
      res.status(404).send('User not found');
    }
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).send('Error changing password');
  }
});

// Change Password Admin
app.post('/change-password-admin', async (req, res) => {
  console.log('POST /change-password-admin', req.body);
  try {
    const { email, newPassword, admin_type } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const admin = await Admin.findOneAndUpdate(
      { email, admin_type },
      { password: hashedPassword },
      { new: true }
    );
    if (admin) {
      res.send('Password changed successfully');
    } else {
      res.status(404).send('Admin not found');
    }
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).send('Error changing password');
  }
});

// Upload User Image
app.post('/upload-image-user', upload.single('image'), async (req, res) => {
  console.log('POST /upload-image-user', req.body);
  try {
    const { email } = req.body;
    const user = await User.findOneAndUpdate(
      { email },
      { image: req.file ? `/uploads/${req.file.filename}` : null },
      { new: true }
    );
    if (user) {
      res.send('Image uploaded successfully');
    } else {
      res.status(404).send('User not found');
    }
  } catch (err) {
    console.error('Error uploading image:', err);
    res.status(500).send('Error uploading image');
  }
});

// Upload Admin Image
app.post('/upload-image-admin', upload.single('image'), async (req, res) => {
  console.log('POST /upload-image-admin', req.body);
  try {
    const { email, admin_type } = req.body;
    const admin = await Admin.findOneAndUpdate(
      { email, admin_type },
      { image: req.file ? `/uploads/${req.file.filename}` : null },
      { new: true }
    );
    if (admin) {
      res.send('Image uploaded successfully');
    } else {
      res.status(404).send('Admin not found');
    }
  } catch (err) {
    console.error('Error uploading image:', err);
    res.status(500).send('Error uploading image');
  }
});

// Serve uploaded images
app.use('/uploads', express.static('uploads'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
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
app.use(cors({ origin: '*' })); // Allow all origins for now; update to specific frontend URL in production
app.use(express.json()); // Replace bodyParser.json() with express.json()
app.use(express.static('public'));

// Multer for image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
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
    const existingUser = await User.findOne({ email: new RegExp('^' + email + '$', 'i') });
    if (existingUser) {
      return res.status(400).send('Email already registered');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ ...req.body, password: hashedPassword });
    await newUser.save();
    res.status(200).send('Registration successful');
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
    const existingAdmin = await Admin.findOne({ 
      email: new RegExp('^' + email + '$', 'i'), 
      admin_type 
    });
    if (existingAdmin) {
      return res.status(400).send('Admin already registered for this email and type');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({ ...req.body, password: hashedPassword });
    await newAdmin.save();
    res.status(200).send('Registration successful');
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
    if (!email || !password) {
      return res.status(400).send('Missing email or password');
    }

    // Case-insensitive email lookup
    const user = await User.findOne({ email: new RegExp('^' + email.trim() + '$', 'i') });
    if (!user) {
      console.log(`User not found for email: ${email}`);
      return res.status(404).send('User not found');
    }

    // Check if the stored password is hashed (starts with $2b)
    const isHashed = user.password.startsWith('$2b$');
    let isMatch;

    if (isHashed) {
      // Compare with bcrypt if hashed
      isMatch = await bcrypt.compare(password.trim(), user.password);
    } else {
      // Direct comparison if plaintext (temporary fix)
      console.warn(`Plaintext password detected for user ${email}. Please update to hashed password.`);
      isMatch = password.trim() === user.password.trim();
    }

    if (isMatch) {
      console.log(`Login successful for user: ${email}`);
      res.status(200).send('Login successful');
    } else {
      console.log(`Invalid password for user: ${email}`);
      return res.status(401).send('Invalid password');
    }
  } catch (err) {
    console.error('Error during user login:', err);
    res.status(500).send(`Error during login: ${err.message}`);
  }
});

// Login Admin
app.post('/login-admin', async (req, res) => {
  console.log('POST /login-admin', req.body);
  try {
    const { email, password, admin_type } = req.body;
    if (!email || !password || !admin_type) {
      return res.status(400).send('Missing required fields');
    }

    // Case-insensitive email lookup
    const admin = await Admin.findOne({ 
      email: new RegExp('^' + email.trim() + '$', 'i'), 
      admin_type 
    });
    if (!admin) {
      console.log(`Admin not found for email: ${email}, admin_type: ${admin_type}`);
      return res.status(404).send('Admin not found');
    }

    // Check if the stored password is hashed
    const isHashed = admin.password.startsWith('$2b$');
    let isMatch;

    if (isHashed) {
      isMatch = await bcrypt.compare(password.trim(), admin.password);
    } else {
      console.warn(`Plaintext password detected for admin ${email}. Please update to hashed password.`);
      isMatch = password.trim() === admin.password.trim();
    }

    if (isMatch) {
      console.log(`Login successful for admin: ${email}`);
      res.status(200).send('Login successful');
    } else {
      console.log(`Invalid password for admin: ${email}`);
      return res.status(401).send('Invalid password');
    }
  } catch (err) {
    console.error('Error during admin login:', err);
    res.status(500).send(`Error during login: ${err.message}`);
  }
});

// Get User Data
app.post('/user-data', async (req, res) => {
  console.log('POST /user-data', req.body);
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: new RegExp('^' + email.trim() + '$', 'i') }).select('-password');
    if (user) {
      res.status(200).json(user);
    } else {
      res.status(404).send('User not found');
    }
  } catch (err) {
    console.error('Error fetching user data:', err);
    res.status(500).send(`Error fetching user data: ${err.message}`);
  }
});

// Get Admin Data
app.post('/admin-data', async (req, res) => {
  console.log('POST /admin-data', req.body);
  try {
    const { email, admin_type } = req.body;
    const admin = await Admin.findOne({ 
      email: new RegExp('^' + email.trim() + '$', 'i'), 
      admin_type 
    }).select('-password');
    if (admin) {
      res.status(200).json(admin);
    } else {
      res.status(404).send('Admin not found');
    }
  } catch (err) {
    console.error('Error fetching admin data:', err);
    res.status(500).send(`Error fetching admin data: ${err.message}`);
  }
});

// Change Password User
app.post('/change-password-user', async (req, res) => {
  console.log('POST /change-password-user', req.body);
  try {
    const { email, newPassword } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const user = await User.findOneAndUpdate(
      { email: new RegExp('^' + email.trim() + '$', 'i') },
      { password: hashedPassword },
      { new: true }
    );
    if (user) {
      res.status(200).send('Password changed successfully');
    } else {
      res.status(404).send('User not found');
    }
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).send(`Error changing password: ${err.message}`);
  }
});

// Change Password Admin
app.post('/change-password-admin', async (req, res) => {
  console.log('POST /change-password-admin', req.body);
  try {
    const { email, newPassword, admin_type } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const admin = await Admin.findOneAndUpdate(
      { email: new RegExp('^' + email.trim() + '$', 'i'), admin_type },
      { password: hashedPassword },
      { new: true }
    );
    if (admin) {
      res.status(200).send('Password changed successfully');
    } else {
      res.status(404).send('Admin not found');
    }
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).send(`Error changing password: ${err.message}`);
  }
});

// Upload User Image
app.post('/upload-image-user', upload.single('image'), async (req, res) => {
  console.log('POST /upload-image-user', req.body);
  try {
    const { email } = req.body;
    const user = await User.findOneAndUpdate(
      { email: new RegExp('^' + email.trim() + '$', 'i') },
      { image: req.file ? `/uploads/${req.file.filename}` : null },
      { new: true }
    );
    if (user) {
      res.status(200).send('Image uploaded successfully');
    } else {
      res.status(404).send('User not found');
    }
  } catch (err) {
    console.error('Error uploading image:', err);
    res.status(500).send(`Error uploading image: ${err.message}`);
  }
});

// Upload Admin Image
app.post('/upload-image-admin', upload.single('image'), async (req, res) => {
  console.log('POST /upload-image-admin', req.body);
  try {
    const { email, admin_type } = req.body;
    const admin = await Admin.findOneAndUpdate(
      { email: new RegExp('^' + email.trim() + '$', 'i'), admin_type },
      { image: req.file ? `/uploads/${req.file.filename}` : null },
      { new: true }
    );
    if (admin) {
      res.status(200).send('Image uploaded successfully');
    } else {
      res.status(404).send('Admin not found');
    }
  } catch (err) {
    console.error('Error uploading image:', err);
    res.status(500).send(`Error uploading image: ${err.message}`);
  }
});

// Serve uploaded images
app.use('/uploads', express.static('uploads'));

// Get Emergency Messages
app.get('/get-emergency-messages', (req, res) => {
  console.log('GET /get-emergency-messages');
  try {
    // Sample emergency messages (replace with your data source, e.g., MongoDB)
    const emergencyMessages = [
      { text: 'Emergency: Flood alert in Dhaka at 03:40 PM, June 13, 2025' },
      { text: 'Alert: Road closure on Main Street due to accident' }
    ];
    res.status(200).json(emergencyMessages);
  } catch (err) {
    console.error('Error fetching emergency messages:', err);
    res.status(500).send('Error fetching emergency messages');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
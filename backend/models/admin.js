const mongoose = require('mongoose');
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true },
  username: { type: String, required: true },
  admin_type: { type: String, required: true },
  country: { type: String, required: true },
  thana: { type: String, required: true },
  emergency_response: String,
  service_info: String,
  latitude: String,
  longitude: String,
  password: { type: String, required: true },
  image: String
});
module.exports = mongoose.model('Admin', adminSchema);
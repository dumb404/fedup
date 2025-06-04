const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  first_name: { type: String, required: true },
  last_name: { type: String, required: true },
  driving_license: String,
  national_id: String,
  number_plate: String,
  address: String,
  location: String,
  latitude: String,
  longitude: String,
  password: { type: String, required: true },
  country: { type: String, required: true },
  emergency_contact_number: String,
  emergency_contact_number_of_a_related_person: String,
  image: String
});
module.exports = mongoose.model('User', userSchema);
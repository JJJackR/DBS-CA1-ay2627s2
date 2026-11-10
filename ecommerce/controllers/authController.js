const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const authModel = require("../models/authModel");

const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    if (!username || !password) {
      return res.status(400).json({ success: false, message: "Username and password are required." });
    }
    const member = await authModel.findByUsername(username);
    if (!member) {
      return res.status(401).json({ success: false, message: "Invalid username or password." });
    }
    const isMatch = await bcrypt.compare(password, member.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Invalid username or password." });
    }
    const token = jwt.sign(
      { id: member.id, username: member.username, role: member.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    res.json({ success: true, token, member: { id: member.id, username: member.username, role: member.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error." });
  }
};

const register = async (req, res) => {
  const { username, email, dob, password, gender } = req.body;
  try {
    if (!username || !email || !dob || !password || !gender) {
      return res.status(400).json({ success: false, message: "All fields are required." });
    }
    const existing = await authModel.findByUsername(username);
    if (existing) {
      return res.status(409).json({ success: false, message: "Username already exists." });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const member = await authModel.createMember(username, email, dob, hashedPassword, gender);
    res.status(201).json({ success: true, message: "Registration successful.", member });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error." });
  }
};

module.exports = { login, register };
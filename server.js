const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const twilio = require('twilio');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const jwt = require('jsonwebtoken');

dotenv.config();

const DBURL = process.env.MONGODB_URI
const IP = "192.168.29.14"; // Your server's IP address

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'default_secret',
    resave: false,
    saveUninitialized: false, // Ensure only initialized sessions are saved
    store: MongoStore.create({ mongoUrl: DBURL }), // MongoDB session storage
    
}));


app.use((req, res, next) => {
    console.log(`Session Data: ${JSON.stringify(req.session)}`);
    next();
});

mongoose.connect(DBURL)
    .then(() => console.log('MongoDB Atlas connected successfully'))
    .catch(err => console.error('MongoDB connection error:', err));

app.get('/', (req, res) => {
    res.send('Welcome to the Train Check-In API!'); // Customize this message
});

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    mobile: { type: String, required: true },
    password: { type: String, required: true },
    aadhaarNumber: { type: String, required: true },
    pnr: { type: String, required: false }, // PNR is now provided by the client
    resetPasswordToken: String,
    resetPasswordExpires: Date,
});

const User = mongoose.model('User ', userSchema); // Fixed model name

// Journey Schema
const journeySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User ' },
    pnr: { type: String, required: true },
    trainNumber: { type: String, required: true },
    departure: { type: String, required: true },
    arrival: { type: String, required: true },
    date: { type: Date, required: true },
    status: { type: String, required: true },
});

const Journey = mongoose.model('Journey', journeySchema); // Fixed model name

// Twilio Client
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const otps={};

// Endpoint to send OTP
app.post('/send-otp', async (req, res) => {
    const { mobile } = req.body;
    if (!mobile) {
        return res.status(400).send('Mobile number is required.');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log(`Generated OTP: ${otp}`);

    try {
        await twilioClient.messages.create({
            body: `Your OTP is ${otp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: mobile,
        });

        // Store OTP temporarily
        otps[mobile] = otp; // Store OTP against the mobile number
        console.log(`OTP sent to ${mobile}: ${otp}`);

        res.status(200).send('OTP sent successfully');
    } catch (error) {
        console.error('Error sending OTP:', error);
        res.status(500).send('Internal server error');
    }
});

// Endpoint to verify OTP
app.post('/verify-otp', (req, res) => {
    console.log('Received request:', req.body)
    const { mobile, otp } = req.body;
    if (!mobile || !otp) {
        return res.status(400).json({ message: 'Mobile number and OTP are required.' });
    }

    // Check if the OTP matches
    if (otps[mobile] && otps[mobile] === otp) {
        delete otps[mobile]; // Clear OTP after successful verification
        return res.status(200).json({ message: 'OTP verified successfully' });
    } else {
        return res.status(400).json({ message: 'Invalid OTP' });
    }
});

// Signup Endpoint
app.post('/signup', async (req, res) => {
    const { name, email, mobile, password, aadhaarNumber } = req.body; // PNR is not expected from the client
    if (!name || !email || !mobile || !password || !aadhaarNumber) {
        return res.status(400).send('All fields are required.');
    }
    try {
        // Check if the mobile number or Aadhaar number already exists
        const existingUserByMobile = await User.findOne({ mobile });
        if (existingUserByMobile) {
            return res.status(400).send('You are already registered with this mobile number.');
        }

        const existingUserByAadhaar = await User.findOne({ aadhaarNumber });
        if (existingUserByAadhaar) {
            return res.status(400).send('You are already registered with this Aadhaar number.');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        // Remove pnr from the user creation if it's not provided
        const newUser  = new User({ name, email, mobile, password: hashedPassword, aadhaarNumber });
        await newUser .save();
        res.status(201).send('User  registered successfully');
    } catch (error) {
        console.error('Error registering user:', error); // Log the error
        res.status(500).send('Error registering user: ' + error.message);
    }
});

// Login Endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send('Email and password are required.');
    }
    try {
        const user = await User.findOne({ email });
        if (!user) {
            console.log(`Login attempt failed: User not found for email: ${email}`);
            return res.status(401).send('Invalid credentials');
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.log(`Login attempt failed: Invalid password for email: ${email}`);
            return res.status(401).send('Invalid credentials');
        }

        const response = {
            message: 'Login successful',
            user: {
                name: user.name,
                email: user.email,
                mobile: user.mobile,
                aadhaarNumber: user.aadhaarNumber,
                pnr: user.pnr // Include the user's PNR here
            }
        };
        console.log(`User  logged in successfully: ${email}`); // Log successful login
        res.status(200).json(response);
    } catch (error) {
        console.error('Error during login:', error); // Log the error
        res.status(500).send('Internal server error');
    }
});

app.post('/validate-biometric', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ message: "Token is required." });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err) => {
        if (err) {
            return res.status(401).json({ message: "Invalid or expired token." });
        }

        res.status(200).json({
            message: "Biometric validation successful."
        });
    });
});


// Send Reset Email Endpoint
app.post('/send-reset-email', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).send('Email is required.');
    }
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).send('User  not found.');
        }

        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // Token valid for 1 hour
        await user.save();

        const resetLink = `http://${IP}:4000/reset-password?token=${token}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset',
            text: `Click the link to reset your password: ${resetLink}`,
        };

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        await transporter.sendMail(mailOptions);
        res.status(200).send('Password reset link has been sent to your email.');
    } catch (error) {
        console.error('Error sending reset email:', error);
        res.status(500).send('Internal server error');
    }
});

// GET Reset Password Endpoint
app.get('/reset-password', async (req, res) => {
    const { token } = req.query;
    if (!token) {
        return res.status(400).send('Token is required.');
    }

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send('Invalid or expired token.');
        }

        // Here you can render a password reset form or return a success message
        // For example, you can send an HTML page or a JSON response
        res.status(200).send('Token is valid. Please provide a new password.'); // Placeholder response
    } catch (error) {
        console.error('Error validating token:', error);
        res.status(500).send('Internal server error');
    }
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
        return res.status(400).send('Token and new password are required.');
    }

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).send('Invalid or expired token.');
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).send('Password has been reset successfully.');
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).send('Internal server error');
    }
});

// Fetch Journeys Endpoint
app.post('/fetch-journeys', async (req, res) => {
    const { pnr, date } = req.body;
    if (!pnr || !date) {
        return res.status(400).send('PNR and date are required.');
    }
    try {
        const journeys = await Journey.find({
            pnr: pnr,
            date: {
                $gte: new Date(date),
                $lt: new Date(new Date(date).setDate(new Date(date).getDate() + 1))
            }
        });
        if (journeys.length === 0) {
            return res.status(200).json([]); // Return empty array if none found
        }
        res.status(200).json(journeys);
    } catch (error) {
        console.error('Error fetching journeys:', error); // Log the error
        res.status(500).send('Error fetching journeys: ' + error.message);
    }
});

// Journey Details Endpoint
app.post('/journey-details', async (req, res) => {
    const { pnr } = req.body;
    if (!pnr) {
        return res.status(400).send('PNR is required.');
    }
    try {
        const journey = await Journey.findOne({ pnr });
        if (!journey) {
            return res.status(404).send('Journey not found.');
        }
        res.status(200).json(journey);
    } catch (error) {
        console.error('Error fetching journey details:', error); // Log the error
        res.status(500).send('Error fetching journey details: ' + error.message);
    }
});

// Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next(); // User is authenticated
    }
    return res.status(401).send('Unauthorized');
}

// Protected Route Example
app.get('/protected-route', isAuthenticated, (req, res) => {
    res.send('This is a protected route.');
});

// Start the server
const PORT = process.env.PORT || 4000;
app.listen(PORT, IP, () => {
    console.log(`Server is running on http://${IP}:${PORT}`);
});
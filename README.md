# Train Check-In API

## Overview

The Train Check-In API is a Node.js application built with Express.js that provides backend services for a train check-in system. It allows users to register, log in, verify OTPs, reset passwords, and manage their train journeys.

## Features

- User registration and authentication
- OTP (One-Time Password) generation and verification
- Password reset functionality via email
- Journey management (fetching and viewing journey details)
- Biometric validation (JWT-based)
- Session management with MongoDB
- Email notifications using Nodemailer
- Twilio integration for SMS notifications

## Technologies Used

- Node.js
- Express.js
- MongoDB (with Mongoose)
- Twilio for SMS
- Nodemailer for email notifications
- JSON Web Tokens (JWT) for authentication
- bcrypt for password hashing
- dotenv for environment variable management
- cors for Cross-Origin Resource Sharing
- body-parser for parsing request bodies
- express-session for session management

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MongoDB (local or Atlas)
- Twilio account for SMS functionality
- Gmail account for sending emails (or any other SMTP service)

Contributing
Contributions are welcome! If you have suggestions for improvements or new features, please open an issue or submit a pull request.

License
This project is licensed under the MIT License - see the LICENSE file for details.

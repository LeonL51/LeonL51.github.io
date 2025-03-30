// Node.Js Server 
const express = require('express'); // Framework for building the web server
const nodemailer = require('nodemailer'); // Library to send emails
// Middleware 
const bodyParser = require('body-parser'); // Parse request bodies
const rateLimit = require('express-rate-limit'); // Limit repeated requests to APIs
const cors = require('cors'); // Handle Cross-Origin Resource Sharing (CORS)
// Securities 
const dotenv = require('dotenv'); // Manage environment variables
const validator = require('validator'); // Validate and sanitize user input
const helmet = require('helmet'); // Adds security headers to HTTP responses


dotenv.config(); // Load environment variables from .env file

const app = express(); 
const PORT = 3000; // Define the port for the server

// Security Enhancement: Use Helmet to set secure HTTP headers
app.use(helmet()); // Protects against some well-known vulnerabilities by setting appropriate headers

// CORS Configuration: Allow requests from specific origins (e.g., your frontend application)
app.use(cors({
    origin: ['https://yourfrontend.com'], // Replace with the actual domain of your frontend
    methods: ['POST'], // Restrict HTTP methods to those necessary
})); // Adds CORS headers to prevent unauthorized cross-origin requests

// Middleware: functions that process requests before they reach the route handler
// Extended: true -> Supports objects and arrays in URL-encoded format 
app.use(bodyParser.urlencoded({ extended: true })); // Parses form submissions (URL-encoded data)
app.use(bodyParser.json()); // Parses JSON data from requests

// Apply rate limiting to prevent abuse
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: 'Too many requests from this IP, please try again later.', // Message returned when limit is exceeded
});
app.use('/send-email', limiter); // Apply rate limiting to the /send-email endpoint

// Email configuration using Nodemailer
const transporter = nodemailer.createTransport({
    service: 'Gmail', // Specify the email service (e.g., Gmail)
    auth: {
        user: process.env.EMAIL, // Email address loaded from environment variables
        pass: process.env.PASSWORD, // App-specific password or email password from environment variables
    },
});

// Handle POST requests to /send-email
app.post('/send-email', (req, res) => {
    // Extract form data from request
    const { name, email, message, subject } = req.body;

    // Validate email 
    if (!validator.isEmail(email)) {
        // Return 400 response if the email is invalid
        return res.status(400).send(`Invalid email address.`);
    }

    // Validate and sanitize the name field
    if (!validator.isLength(name, { min: 1, max: 100 })) {
        return res.status(400).send('Invalid name length. Name must be between 1 and 100 characters.');
    }

    // Validate and sanitize the message field
    if (!validator.isLength(message, { min: 1, max: 1000 })) {
        return res.status(400).send('Message is too long. Maximum length is 1000 characters.');
    }

    // Sanitize and escape potentially harmful content
    const sanitizedMessage = validator.escape(message); // Escape potentially harmful characters in the message
    const sanitizedSubject = validator.escape(subject || 'Message'); // Escape the subject or provide a default

    // Define email options for sending
    const mailOptions = {
        from: process.env.EMAIL, // Sender's email (must match the authenticated email)
        to: process.env.EMAIL, // Recipient email address
        replyTo: email, // Reply-To address (user's email)
        subject: sanitizedSubject, // Sanitized subject
        text: `Name: ${name}\nEmail: ${email}\nMessage: ${sanitizedMessage}`, // Email body with sanitized inputs
    };

    // Send the email using Nodemailer
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            res.status(500).send('Something went wrong. Please try again later.');
            // Outputs error details to debug
            console.error('Error sending email:', error);
        } else {
            console.log('Email sent:', info.response); // Log success message
            res.status(200).send('Message sent successfully!'); // Return success response to the client
        }
    });
});

// Start the server and listen on the specified port
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`); // Log server startup success message
});

// Additional Notes:
// - Added Helmet for setting secure HTTP headers to reduce attack surface
// - Implemented CORS to restrict cross-origin access to the API
// - Sanitized inputs to avoid injection attacks (e.g., XSS, command injection)
// - Improved validation for "name" and "message" fields with length constraints
// - Make sure to replace 'https://yourfrontend.com' with your frontend's actual URL

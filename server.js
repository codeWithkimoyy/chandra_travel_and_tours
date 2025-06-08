const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const mongoose = require('mongoose');
const { ObjectId } = mongoose.Types;
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const rateLimit = require('express-rate-limit');
const MongoStore = require('connect-mongo');
require('dotenv').config();

const app = express();
const PORT = 3000;

// Define admin emails from environment variable
const adminEmails = (process.env.ADMIN_EMAILS || 'janely193.jc@gmail.com,cutamorakim15@gmail.com').split(',');

// MongoDB Connection URI from environment
const uri = process.env.MONGODB_URI || "mongodb+srv://cutamorakim15:q5QwLo6fQJk1oXGk@chandratravelandtours.0pnl19g.mongodb.net/chandraTravelDB?retryWrites=true&w=majority&appName=ChandraTravelandTours";

// Configure different rate limiters for different types of routes
//const generalLimiter = rateLimit({
//    windowMs: 15 * 60 * 1000, // 15 minutes
 //   max: 1000, // Increased to 1000 requests per window for general routes
//    message: 'Too many requests from this IP, please try again later.',
//    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
//    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
// });

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 999999, // Very high limit
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 50, // 50 login attempts per hour
    message: 'Too many login attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const formSubmissionLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 20, // 20 form submissions per hour per IP
    message: 'Too many form submissions, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply rate limiting to specific routes
app.use('/api/auth', authLimiter); // Stricter limits for auth routes
app.use('/api/psa-birth', formSubmissionLimiter);
app.use('/api/psa-marriage', formSubmissionLimiter);
app.use('/api/psa-death', formSubmissionLimiter);
app.use('/api/marina-srb', formSubmissionLimiter);
app.use('/api/marina-sid', formSubmissionLimiter);
app.use('/api/visa', formSubmissionLimiter);
app.use('/api/insurance', formSubmissionLimiter);
app.use('/api/booking', formSubmissionLimiter);
app.use('/api/ferry', formSubmissionLimiter);
app.use('/api/tour', formSubmissionLimiter);
app.use('/api/cfo', formSubmissionLimiter);
app.use('/api/apostille', formSubmissionLimiter);
app.use('/api/oec-bm', formSubmissionLimiter);
app.use('/api/oec-exemption', formSubmissionLimiter);
app.use('/api/nbi', formSubmissionLimiter);
app.use('/api/ereg', formSubmissionLimiter);
app.use('/api/quarantine-cert', formSubmissionLimiter);
app.use('/api/quarantine-vacc', formSubmissionLimiter);
app.use('/api/passport', formSubmissionLimiter);
app.use('/api/cenomar', formSubmissionLimiter);
app.use('/api/embassy', formSubmissionLimiter);
app.use('/api/cav-cana', formSubmissionLimiter);
app.use('/api/lto', formSubmissionLimiter);
app.use('/api/voters', formSubmissionLimiter);
app.use('/api/load-bills', formSubmissionLimiter);
app.use('/api/airline-ticketing', formSubmissionLimiter);
app.use('/api/police', formSubmissionLimiter);
app.use('/api/contact', formSubmissionLimiter);

// Apply general rate limiting to all other routes
app.use(generalLimiter);

// Connect to MongoDB using Mongoose
mongoose.connect(uri)
  .then(() => {
    console.log('Connected to MongoDB Atlas successfully!');
    // Get the database instance
    db = mongoose.connection.db;
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1);
  });

// Middleware - Order is important!
app.use(cors({
    origin: process.env.CLIENT_URL || 'https://chandra-travel-and-tours-cjf6.onrender.com', // Updated for Render deployment
    credentials: true  // Allow credentials (cookies) to be sent
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configure express-session middleware with environment variables
app.use(session({
    secret: process.env.SESSION_SECRET || 'your_session_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // Set to true in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax'
    },
    name: 'sessionId',
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI || "mongodb+srv://cutamorakim15:q5QwLo6fQJk1oXGk@chandratravelandtours.0pnl19g.mongodb.net/chandraTravelDB?retryWrites=true&w=majority&appName=ChandraTravelandTours",
        ttl: 14 * 24 * 60 * 60 // 14 days
    })
}));

// Initialize Passport and restore authentication state, if any, from the session.
app.use(passport.initialize());
app.use(passport.session());

// Passport Google OAuth 2.0 Strategy configuration with environment variables
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
},
function(accessToken, refreshToken, profile, cb) {
    // This function is called after successful Google authentication.
    // Find or create a user in your database here.

    // Check if the database connection is available
    if (!db) {
        console.error("Database not connected.");
        return cb(new Error("Database not available."));
    }

    const usersCollection = db.collection('users');

    // Use profile.id for Google's unique user ID
    usersCollection.findOne({ googleId: profile.id })
        .then(existingUser => {
            if (existingUser) {
                // User already exists, update last login date and return
                console.log("Existing user logged in:", existingUser.email);
                // Ensure userType is set, default to 'client' if not present
                const userType = adminEmails.includes(existingUser.email) ? 'admin' : (existingUser.userType || 'client');
                
                // Also ensure the name and picture are updated if profile.displayName/photos is available and better
                const updatedName = profile.displayName || existingUser.name || existingUser.email;
                const updatedPicture = (profile.photos && profile.photos.length > 0) ? profile.photos[0].value : existingUser.picture || null;

                usersCollection.updateOne(
                    { _id: existingUser._id },
                    { $set: { lastLoginDate: new Date(), userType: userType, name: updatedName, picture: updatedPicture } }
                );
                return cb(null, {...existingUser, userType: userType, name: updatedName, picture: updatedPicture}); // Return updated user object
            } else {
                // User does not exist, create a new user
                // Determine user type
                const userEmail = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
                const userType = (userEmail && adminEmails.includes(userEmail)) ? 'admin' : 'client';

                const newUser = {
                    googleId: profile.id,
                    email: userEmail,
                    name: profile.displayName || userEmail || null, // Ensure name is populated, fallback to email
                    picture: (profile.photos && profile.photos.length > 0) ? profile.photos[0].value : null, // Store profile picture URL
                    registrationDate: new Date(),
                    lastLoginDate: new Date(),
                    userType: userType // Assign user type
                };

                usersCollection.insertOne(newUser)
                    .then(result => {
                        console.log("New user created:", newUser.email, "Type:", newUser.userType);
                        // Return the newly created user (MongoDB insertOne adds _id to the object)
                        return cb(null, newUser);
                    })
                    .catch(err => {
                        console.error("Error creating new user:", err);
                        return cb(err);
                    });
            }
        })
        .catch(err => {
            console.error("Error finding user:", err);
            return cb(err);
        });
}
));

// Serialize user into the session
passport.serializeUser(function(user, done) {
    // Use the MongoDB user ID for serialization
    done(null, user._id);
});

// Deserialize user from the session
passport.deserializeUser(function(id, done) {
    console.log("Attempting to deserialize user with ID:", id);
    // Find the user in the database by ID
    if (!db) {
        console.error("Database not connected for deserialization.");
        return done(new Error("Database not available."));
    }
    const usersCollection = db.collection('users');
    // Need to convert the id string back to a MongoDB ObjectId
    try {
        const objectId = new ObjectId(id);
        usersCollection.findOne({ _id: objectId })
            .then(user => {
                if (user) {
                    console.log("User deserialized successfully:", user.email, "Type:", user.userType);
                    done(null, user);
                } else {
                    console.warn("User not found during deserialization for ID:", id);
                    done(null, false); // User not found
                }
            })
            .catch(err => {
                console.error("Error deserializing user:", err);
                done(err);
            });
    } catch (e) {
        console.error("Invalid ObjectId in deserializeUser:", id, e);
        done(e);
    }
});

// Nodemailer transporter with environment variables
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'janely193.jc@gmail.com',
        pass: process.env.EMAIL_PASS || 'haqprygxuijpzpjb'
    },
    debug: process.env.NODE_ENV === 'development',
    logger: process.env.NODE_ENV === 'development'
});

// Verify transporter connection
transporter.verify(function(error, success) {
    if (error) {
        console.error('SMTP connection error:', error);
        console.log('Email functionality will be disabled');
    } else {
        console.log('SMTP server is ready to take our messages');
    }
});

// Helper function to format form data for email
function formatFormDataForEmail(data, formType) {
    let emailContent = `<h2>${formType} Form Submission</h2><br>`;
    emailContent += `<p><strong>Request ID:</strong> ${data._id}</p><br>`; // Display MongoDB _id
    emailContent += '<h3>Submitted Details:</h3>';
    emailContent += '<table style="border-collapse: collapse; width: 100%;">';
    emailContent += '<tr style="background-color: #f2f2f2;"><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Field</th><th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Value</th></tr>';
    
    // Filter out _id from the table since we already displayed it
    const { _id, ...formData } = data;
    
    for (const [key, value] of Object.entries(formData)) {
        const formattedKey = key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
        emailContent += `<tr>
            <td style="border: 1px solid #ddd; padding: 8px;">${formattedKey}</td>
            <td style="border: 1px solid #ddd; padding: 8px;">${value}</td>
        </tr>`;
    }
    
    emailContent += '</table>';
    return emailContent;
}

// Helper function to send email
async function sendFormEmail(formType, data) {
    console.log(`[sendFormEmail] Attempting to send email for formType: ${formType}`);
    console.log(`[sendFormEmail] Email data received:`, data);
    console.log(`[sendFormEmail] data.email: ${data.email}, data.name: ${data.name}`);

    const senderEmail = process.env.EMAIL_USER; // Explicitly use the sending email account
    const senderName = data.name || data.clientName || 'No Name Provided';
    const fromAddress = `"${senderName}" <${senderEmail}>`; // Dynamically set the email address in the 'From' field

    const mailOptions = {
        from: fromAddress,
        to: adminEmails.join(', '),
        subject: `New ${formType} Form Submission`,
        html: formatFormDataForEmail(data, formType),
        replyTo: data.email || 'janely193.jc@gmail.com' // Ensures replies go to the user's email
    };

    try {
        console.log("[sendFormEmail] Sending mail with options:", mailOptions);
        await transporter.sendMail(mailOptions);
        console.log(`[sendFormEmail] ${formType} form email sent successfully`);
        return true;
    } catch (error) {
        console.error(`[sendFormEmail] Error sending ${formType} form email:`, error);
        return false;
    }
}

// Middleware to ensure user is authenticated
function ensureAuthenticated(req, res, next) {
    if (!req.session || !req.session.passport) {
        console.log("Access Denied: No session or passport data");
        return res.status(401).json({ 
            message: "Unauthorized: Please log in.",
            code: "AUTH_REQUIRED"
        });
    }

    if (req.isAuthenticated()) {
        // Ensure user object is properly attached
        if (!req.user || !req.user._id) {
            console.log("Access Denied: Invalid user object in session");
            return res.status(401).json({ 
                message: "Session expired. Please log in again.",
                code: "SESSION_INVALID"
            });
        }
        return next();
    }

    console.log("Access Denied: User not authenticated");
    return res.status(401).json({ 
        message: "Unauthorized: Please log in.",
        code: "AUTH_REQUIRED"
    });
}

// Middleware to ensure user is an admin
function ensureAdmin(req, res, next) {
    console.log("Checking admin privileges...");
    if (req.isAuthenticated() && req.user && req.user.userType === 'admin') {
        console.log("User authenticated and is admin. Proceeding.", "User object:", req.user, "User type:", req.user.userType);
        return next();
    } else {
        console.log("Access Denied: User is not an admin or not authenticated.", req.user ? req.user.email : 'N/A', "Detected userType:", req.user ? req.user.userType : 'N/A');
    res.status(403).json({ message: "Forbidden: You do not have admin privileges." });
    }
}

// Authentication Routes

// Initiate Google authentication
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google authentication callback
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    function(req, res) {
        // Successful authentication, redirect to the appropriate dashboard.
        if (req.user.userType === 'admin') {
            res.redirect('/admin-dashboard.html');
        } else {
            res.redirect('/my-requests.html');
        }
    });

// Logout endpoint
app.post('/api/auth/logout', ensureAuthenticated, (req, res) => {
    console.log("Received request for /api/auth/logout");
    req.logout(function(err) {
        if (err) {
            console.error("Error during req.logout():", err);
            return res.status(500).json({ message: "Logout failed." });
        }
        console.log("User successfully logged out from Passport session.");
        req.session.destroy(function(err) {
            if (err) {
                 console.error("Error destroying session after logout:", err);
                 // Even if session destroy fails, try to clear cookie and send success if req.logout was fine.
                 // This handles cases where session might not exist or is already destroyed, but we want clean client state
                 res.clearCookie('connect.sid');
                 return res.status(500).json({ message: "Logout failed due to session error." });
            } else {
                console.log("Session destroyed successfully.");
                res.clearCookie('connect.sid'); // Clear the session cookie
                res.json({ message: "Logout successful." });
            }
        });
    });
});

// Endpoint to check authentication status and return user info
app.get('/api/auth/status', (req, res) => {
    if (req.isAuthenticated()) {
        console.log('Auth status check - User authenticated:', {
            id: req.user._id,
            name: req.user.name,
            email: req.user.email,
            picture: req.user.picture || null
        });
        res.json({
            authenticated: true,
            user: {
                id: req.user._id,
                name: req.user.name,
                email: req.user.email,
                picture: req.user.picture || null
            },
            userType: req.user.userType
        });
    } else {
        console.log('Auth status check - User not authenticated');
        res.json({ authenticated: false });
    }
});

// Helper function to save request to database
async function saveRequest(userId, serviceType, formData, clientName) {
    console.log(`[saveRequest] Attempting to save request for service: ${serviceType}, userId: ${userId}, clientName: ${clientName}`);
    console.log(`[saveRequest] formData:`, formData);

    if (!db) {
        console.error("[saveRequest] Database not connected for saving request.");
        throw new Error("Database not available.");
    }
    if (!userId || !ObjectId.isValid(userId)) {
        console.error(`[saveRequest] Invalid userId provided: ${userId}`);
        throw new Error("Invalid user ID");
    }

    const requestsCollection = db.collection('requests');
    
    const requestDocument = {
        userId: new ObjectId(userId),
        clientName: clientName,
        serviceType: serviceType,
        formData: formData,
        status: "Pending",
        submissionDate: new Date(),
        lastUpdated: new Date()
    };

    try {
        console.log("[saveRequest] Inserting document:", requestDocument);
        const result = await requestsCollection.insertOne(requestDocument);
        if (!result.insertedId) {
            console.error("[saveRequest] Failed to insert request, no insertedId returned.");
            throw new Error("Failed to insert request");
        }
        console.log(`[saveRequest] Request for ${serviceType} saved with MongoDB _id: ${result.insertedId}`);
        return result.insertedId.toString(); // Convert ObjectId to string
    } catch (error) {
        console.error(`[saveRequest] Error saving request for ${serviceType}:`, error);
        throw new Error("Failed to save request: " + error.message);
    }
}

// PSA Birth form submission endpoint
app.post('/api/psa-birth', ensureAuthenticated, async (req, res) => {
    console.log("PSA Birth form submission received");
    const formData = req.body;
    const serviceType = "PSA Birth Certificate";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "PSA Birth form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling PSA Birth form submission:", error);
        res.status(500).json({ message: "Failed to submit PSA Birth form." });
    }
});

// PSA Marriage form submission endpoint
app.post('/api/psa-marriage', ensureAuthenticated, async (req, res) => {
    console.log("PSA Marriage form submission received");
    const formData = req.body;
    const serviceType = "PSA Marriage Certificate";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "PSA Marriage form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling PSA Marriage form submission:", error);
        res.status(500).json({ message: "Failed to submit PSA Marriage form." });
    }
});

// PSA Death form submission endpoint
app.post('/api/psa-death', ensureAuthenticated, async (req, res) => {
    console.log("PSA Death form submission received");
    const formData = req.body;
    const serviceType = "PSA Death Certificate";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "PSA Death form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling PSA Death form submission:", error);
        res.status(500).json({ message: "Failed to submit PSA Death form." });
    }
});

// MARINA SRB form submission endpoint
app.post('/api/marina-srb', ensureAuthenticated, async (req, res) => {
    console.log("MARINA SRB form submission received");
    const formData = req.body;
    const serviceType = "MARINA SRB";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "MARINA SRB form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling MARINA SRB form submission:", error);
        res.status(500).json({ message: "Failed to submit MARINA SRB form." });
    }
});

// MARINA SID form submission endpoint
app.post('/api/marina-sid', ensureAuthenticated, async (req, res) => {
    console.log("MARINA SID form submission received");
    const formData = req.body;
    const serviceType = "MARINA SID";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "MARINA SID form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling MARINA SID form submission:", error);
        res.status(500).json({ message: "Failed to submit MARINA SID form." });
    }
});

// Visa Assistance form submission endpoint
app.post('/api/visa', ensureAuthenticated, async (req, res) => {
    console.log("Visa Assistance form submission received");
    const formData = req.body;
    const serviceType = "Visa Assistance";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "Visa Assistance form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Visa Assistance form submission:", error);
        res.status(500).json({ message: "Failed to submit Visa Assistance form." });
    }
});

// Travel Insurance form submission endpoint
app.post('/api/insurance', ensureAuthenticated, async (req, res) => {
    console.log("Travel Insurance form submission received");
    const formData = req.body;
    const serviceType = "Travel Insurance";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "Travel Insurance form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Travel Insurance form submission:", error);
        res.status(500).json({ message: "Failed to submit Travel Insurance form." });
    }
});

// Flights/Hotel Booking form submission endpoint
app.post('/api/booking', ensureAuthenticated, async (req, res) => {
    console.log("Flights/Hotel Booking form submission received");
    const formData = req.body;
    const serviceType = "Flights/Hotel Booking";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "Flights/Hotel Booking form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Flights/Hotel Booking form submission:", error);
        res.status(500).json({ message: "Failed to submit Flights/Hotel Booking form." });
    }
});

// Ferry/Bus Booking form submission endpoint
app.post('/api/ferry', ensureAuthenticated, async (req, res) => {
    console.log("Ferry/Bus Booking form submission received");
    const formData = req.body;
    const serviceType = "Ferry/Bus Booking";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "Ferry/Bus Booking form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Ferry/Bus Booking form submission:", error);
        res.status(500).json({ message: "Failed to submit Ferry/Bus Booking form." });
    }
});

// Tour Packages form submission endpoint
app.post('/api/tour', ensureAuthenticated, async (req, res) => {
    console.log("Tour Packages form submission received");
    const formData = req.body;
    const serviceType = "Tour Package";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "Tour Package form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Tour Package form submission:", error);
        res.status(500).json({ message: "Failed to submit Tour Package form." });
    }
});

// CFO Appointment form submission endpoint
app.post('/api/cfo', ensureAuthenticated, async (req, res) => {
    console.log("CFO Appointment form submission received");
    const formData = req.body;
    const serviceType = "CFO Appointment";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "CFO Appointment form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling CFO Appointment form submission:", error);
        res.status(500).json({ message: "Failed to submit CFO Appointment form." });
    }
});

// Apostille form submission endpoint
app.post('/api/apostille', ensureAuthenticated, async (req, res) => {
    console.log("Apostille form submission received");
    const formData = req.body;
    const serviceType = "Apostille";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "Apostille form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Apostille form submission:", error);
        res.status(500).json({ message: "Failed to submit Apostille form." });
    }
});

// OEC Balik Manggagawa Appointment form submission endpoint
app.post('/api/oec-bm', ensureAuthenticated, async (req, res) => {
    try {
        const formData = req.body;
        const serviceType = "OEC Balik Manggagawa Appointment";
        const userId = req.user._id;
        const clientName = req.user.name || req.user.email || "Unknown";
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        return res.json({ message: "OEC Balik Manggagawa Appointment form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling OEC Balik Manggagawa Appointment form submission:", error);
        return res.status(500).json({ message: "Failed to submit OEC Balik Manggagawa Appointment form." });
    }
});

// OEC Exemption form submission endpoint
app.post('/api/oec-exemption', ensureAuthenticated, async (req, res) => {
    console.log("OEC Exemption form submission received");
    const formData = req.body;
    const serviceType = "OEC Exemption";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "OEC Exemption form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling OEC Exemption form submission:", error);
        res.status(500).json({ message: "Failed to submit OEC Exemption form." });
    }
});

// NBI form submission endpoint
app.post('/api/nbi', ensureAuthenticated, async (req, res) => {
    console.log("NBI form submission received");
    const formData = req.body;
    const serviceType = "NBI Clearance";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "NBI form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling NBI form submission:", error);
        res.status(500).json({ message: "Failed to submit NBI form." });
    }
});

// eReg form submission endpoint
app.post('/api/ereg', ensureAuthenticated, async (req, res) => {
    console.log("eReg form submission received");
    const formData = req.body;
    const serviceType = "eReg";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "eReg form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling eReg form submission:", error);
        res.status(500).json({ message: "Failed to submit eReg form." });
    }
});

// Quarantine Certificate form submission endpoint
app.post('/api/quarantine-cert', ensureAuthenticated, async (req, res) => {
    console.log("Quarantine Certificate form submission received");
    const formData = req.body;
    const serviceType = "Quarantine Certificate";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "Quarantine Certificate form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Quarantine Certificate form submission:", error);
        res.status(500).json({ message: "Failed to submit Quarantine Certificate form." });
    }
});

// Quarantine Vaccination form submission endpoint
app.post('/api/quarantine-vacc', ensureAuthenticated, async (req, res) => {
    console.log("Quarantine Vaccination form submission received");
    const formData = req.body;
    const serviceType = "Quarantine Vaccination";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "Quarantine Vaccination form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Quarantine Vaccination form submission:", error);
        res.status(500).json({ message: "Failed to submit Quarantine Vaccination form." });
    }
});

// Passport Appointment form submission endpoint
app.post('/api/passport', ensureAuthenticated, async (req, res) => {
    console.log("[api/passport] Passport Appointment form submission received");
    const formData = req.body;
    const serviceType = "Passport Appointment";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        console.log("[api/passport] Attempting to save request and send email...");
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        console.log("[api/passport] Form submitted and email sent successfully.");
        res.json({ message: "Passport Appointment form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("[api/passport] Detailed error handling Passport Appointment form submission:", error);
        // You can check error.name or error.message for more specific handling if needed
        if (error.message.includes("Database not available")) {
            res.status(503).json({ message: "Service Unavailable: Database connection error." });
        } else if (error.message.includes("Failed to save request")) {
            res.status(500).json({ message: "Failed to submit Passport Appointment form due to a database error." });
        } else if (error.message.includes("Error sending")) {
            res.status(500).json({ message: "Passport Appointment form submitted, but email notification failed." });
        } else {
            res.status(500).json({ message: `Failed to submit Passport Appointment form: ${error.message}` });
        }
    }
});

// CENOMAR form submission endpoint
app.post('/api/cenomar', ensureAuthenticated, async (req, res) => {
    console.log("CENOMAR form submission received");
    const formData = req.body;
    const serviceType = "CENOMAR";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "CENOMAR form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling CENOMAR form submission:", error);
        res.status(500).json({ message: "Failed to submit CENOMAR form." });
    }
});

// Embassy Stamping and Translation form submission endpoint
app.post('/api/embassy', ensureAuthenticated, async (req, res) => {
    console.log("Embassy Stamping and Translation form submission received");
    const formData = req.body;
    const serviceType = "Embassy Stamping and Translation";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "Embassy Stamping and Translation form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Embassy Stamping and Translation form submission:", error);
        res.status(500).json({ message: "Failed to submit Embassy Stamping and Translation form." });
    }
});

// CAV and CANA Assistance form submission endpoint
app.post('/api/cav-cana', ensureAuthenticated, async (req, res) => {
    console.log("CAV and CANA Assistance form submission received");
    const formData = req.body;
    const serviceType = "CAV and CANA Assistance";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "CAV and CANA Assistance form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling CAV and CANA Assistance form submission:", error);
        res.status(500).json({ message: "Failed to submit CAV and CANA Assistance form." });
    }
});

// LTO Certificate form submission endpoint
app.post('/api/lto', ensureAuthenticated, async (req, res) => {
    console.log("LTO Certificate form submission received");
    const formData = req.body;
    const serviceType = "LTO Certificate";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "LTO Certificate form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling LTO Certificate form submission:", error);
        res.status(500).json({ message: "Failed to submit LTO Certificate form." });
    }
});

// VOTER'S Certificate from Comelec Main form submission endpoint
app.post('/api/voters', ensureAuthenticated, async (req, res) => {
    console.log("VOTER'S Certificate from Comelec Main form submission received");
    const formData = req.body;
    const serviceType = "VOTER'S Certificate from Comelec Main";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "VOTER'S Certificate from Comelec Main form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling VOTER'S Certificate from Comelec Main form submission:", error);
        res.status(500).json({ message: "Failed to submit VOTER'S Certificate from Comelec Main form." });
    }
});

// Load Available and Bills Payment form submission endpoint
app.post('/api/load-bills', ensureAuthenticated, async (req, res) => {
    try {
        const formData = req.body;
        const serviceType = "Load Available and Bills Payment";
        const userId = req.user._id;
        const clientName = req.user.name || req.user.email || "Unknown";
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        return res.json({ message: "Load Available and Bills Payment form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Load Available and Bills Payment form submission:", error);
        return res.status(500).json({ message: "Failed to submit Load Available and Bills Payment form." });
    }
});

// Airline Ticketing form submission endpoint
app.post('/api/airline-ticketing', ensureAuthenticated, async (req, res) => {
    try {
        const formData = req.body;
        const serviceType = "Airline Ticketing";
        const userId = req.user._id;
        const clientName = req.user.name || req.user.email || "Unknown";
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        return res.json({ message: "Airline Ticketing form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Airline Ticketing form submission:", error);
        return res.status(500).json({ message: "Failed to submit Airline Ticketing form." });
    }
});

// Police Clearance Appointment form submission endpoint
app.post('/api/police', ensureAuthenticated, async (req, res) => {
    try {
        const formData = req.body;
        const serviceType = "Police Clearance Appointment";
        const userId = req.user._id;
        const clientName = req.user.name || req.user.email || "Unknown";
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        return res.json({ message: "Police Clearance Appointment form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling Police Clearance Appointment form submission:", error);
        return res.status(500).json({ message: "Failed to submit Police Clearance Appointment form." });
    }
});

// Contact form submission endpoint
app.post('/api/contact', async (req, res) => {
    console.log("Contact form submission received");
    let { name, email, subject, message } = req.body;

    // If the user is authenticated, override email (and name if not provided) with the logged-in user's email (and name)
    if (req.isAuthenticated() && req.user) {
        email = req.user.email;
        if (!name) {
            name = req.user.name || req.user.email;
        }
    }

    // Basic validation
    if (!name || !email || !subject || (message === undefined)) {
        return res.status(400).json({ message: "All fields are required." });
    }

    try {
        // In a real application, you would save this to a database or send an email.
        // For now, we'll just log it and send a success response.
        console.log("New Contact Us message:", {
            name,
            email,
            subject,
            message,
            timestamp: new Date()
        });

        // Integrate nodemailer (via sendFormEmail) to send an email to the admin accounts.
        await sendFormEmail('Contact Us Message', {
            name,
            email,
            subject,
            message
        });

        res.json({ message: "Your message has been sent successfully! We will get back to you soon." });
    } catch (error) {
        console.error("Error handling contact form submission:", error);
        res.status(500).json({ message: "Failed to send message." });
    }
});

// Helper function to send email notification to admin on status change
async function emailAdminOnStatusChange(requestId, clientName, serviceType, oldStatus, newStatus, clientEmail) {
    const mailOptions = {
        from: `"Admin Notification" <${process.env.EMAIL_USER}>`,
        to: adminEmails.join(', '),
        subject: `Request #${requestId} Status Changed: ${oldStatus} -> ${newStatus}`,
        html: `
            <h2>Request Status Update</h2>
            <p>Dear Admin,</p>
            <p>The status for Request ID <strong>${requestId}</strong> has been updated.</p>
            <ul>
                <li><strong>Client Name:</strong> ${clientName || 'N/A'}</li>
                <li><strong>Client Email:</strong> ${clientEmail || 'N/A'}</li>
                <li><strong>Service Type:</strong> ${serviceType}</li>
                <li><strong>Old Status:</strong> ${oldStatus}</li>
                <li><strong>New Status:</strong> ${newStatus}</li>
            </ul>
            <p>Please log in to the admin dashboard for more details.</p>
            <p>Thank you,</p>
            <p>Chandra Travel and Tours Team</p>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Email notification sent for status change of Request ID ${requestId}`);
    } catch (error) {
        console.error(`Error sending status change email for Request ID ${requestId}:`, error);
        // Do not re-throw, just log the error to avoid blocking the main API response
    }
}

// API to get requests for the logged-in user
app.get('/api/my-requests', ensureAuthenticated, async (req, res) => {
    if (!db) {
        console.error("Database not connected for fetching user requests.");
        return res.status(500).json({ message: "Database not available." });
    }
    const requestsCollection = db.collection('requests');
    const userId = req.user._id; // Get user ID from authenticated user

    try {
        // Find requests where userId matches the logged-in user's ID
        // Explicitly project _id and other necessary fields
        const userRequests = await requestsCollection.find(
            { userId: userId },
            { projection: { _id: 1, serviceType: 1, submissionDate: 1, status: 1, formData: 1, notes: 1, lastUpdated: 1 } } // Project _id
        ).toArray();

        res.json(userRequests);
    } catch (error) {
        console.error("Error fetching user requests:", error);
        res.status(500).json({ message: "Failed to fetch your requests." });
    }
});

// API endpoint to get a single request by ID (for admin and client view)
app.get('/api/requests/:requestId', ensureAuthenticated, async (req, res) => {
    console.log('server.js: Received request for single request details.');
    const requestId = req.params.requestId;
    const user = req.user;

    if (!user) {
        console.log('server.js: User not authenticated.');
        return res.status(401).json({ message: 'Unauthorized: User not authenticated.' });
    }

    if (!db) {
        console.error('server.js: Database not connected for fetching single request.');
        return res.status(500).json({ message: 'Server error: Database not available.' });
    }

    try {
        const requestsCollection = db.collection('requests');
        const objectId = new ObjectId(requestId);
        const request = await requestsCollection.findOne({ _id: objectId });

        if (!request) {
            console.log(`server.js: Request with ID ${requestId} not found.`);
            return res.status(404).json({ message: 'Request not found.' });
        }

        // Only allow admin or the request owner to view details
        const isAdmin = adminEmails.includes(user.email);
        if (!isAdmin && request.userId.toString() !== user._id.toString()) {
            console.log(`server.js: User ${user.email} not authorized to view request ${requestId}.`);
            return res.status(403).json({ message: 'Forbidden: You do not have permission to view this request.' });
        }

        console.log(`server.js: Successfully fetched request ${requestId} for user ${user.email}.`);
        res.json(request);

    } catch (error) {
        console.error('server.js: Error fetching single request:', error);
        // Handle cases where requestId is not a valid ObjectId
        if (error.name === 'BSONError') {
            return res.status(400).json({ message: 'Invalid Request ID format.' });
        }
        res.status(500).json({ message: 'Internal server error while fetching request details.' });
    }
});

// New Admin Export Endpoint (Requires Admin Role)
app.get('/api/admin/export-requests', ensureAdmin, async (req, res) => {
    if (!db) {
        console.error("Database not connected for exporting requests.");
        return res.status(500).json({ message: "Database not available." });
    }
    const requestsCollection = db.collection('requests');

    try {
        // Fetch all requests
        const requests = await requestsCollection.find({}).toArray();

        // Optionally, fetch user details to include client name/email
        const usersCollection = db.collection('users');
        const requestsWithClientData = await Promise.all(requests.map(async request => {
            const user = await usersCollection.findOne({ _id: new ObjectId(request.userId) });
            // Flatten the data for easier processing in a spreadsheet if needed later
            return {
                RequestId: request._id, // Use _id
                ServiceType: request.serviceType,
                Status: request.status,
                SubmissionDate: request.submissionDate,
                ClientName: user ? user.name || user.email : 'Unknown User',
                ClientEmail: user ? user.email : 'Unknown',
                // Include flattened form data - basic example
                ...flattenFormData(request.formData)
            };
        }));

        // Helper function to flatten nested form data
        function flattenFormData(formData, prefix = '') {
            const flatData = {};
            for (const key in formData) {
                if (Object.hasOwnProperty.call(formData, key)) {
                    const newKey = prefix ? `${prefix}.${key}` : key;
                    if (typeof formData[key] === 'object' && formData[key] !== null && !Array.isArray(formData[key])) {
                        Object.assign(flatData, flattenFormData(formData[key], newKey));
                    } else {
                        flatData[newKey] = formData[key];
                    }
                }
            }
            return flatData;
        }

        // Set headers for file download
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=all_requests.json');
        
        // Send the JSON data
        res.json(requestsWithClientData);

    } catch (error) {
        console.error("Error exporting requests:", error);
        res.status(500).json({ message: "Failed to export requests." });
    }
});

// Serve HTML files (should be after API routes to avoid conflicts)
// This might need adjustment based on your exact file serving setup
app.get('/admin-dashboard.html', ensureAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.get('/my-requests.html', ensureAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'my-requests.html'));
});

// Admin check endpoint
app.get('/api/check-admin', ensureAuthenticated, (req, res) => {
    if (req.user && req.user.userType === 'admin') {
        res.json({ isAdmin: true });
    } else {
        res.status(403).json({ isAdmin: false, message: 'Unauthorized access' });
    }
});

// Admin statistics endpoint
app.get('/api/admin/stats', ensureAuthenticated, ensureAdmin, async (req, res) => {
    try {
        const requestsCollection = db.collection('requests');
        const usersCollection = db.collection('users');

        // Get total requests
        const totalRequests = await requestsCollection.countDocuments();
        
        // Get pending requests
        const pendingRequests = await requestsCollection.countDocuments({ status: 'Pending' });
        
        // Get completed requests today
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const completedToday = await requestsCollection.countDocuments({
            status: 'Approved',
            lastUpdated: { $gte: today }
        });
        
        // Get active users (users who logged in within last 30 days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        const activeUsers = await usersCollection.countDocuments({
            lastLoginDate: { $gte: thirtyDaysAgo }
        });

        // Calculate trends (comparing with previous period)
        const previousPeriod = new Date();
        previousPeriod.setDate(previousPeriod.getDate() - 30);
        
        const currentPeriodRequests = await requestsCollection.countDocuments({
            submissionDate: { $gte: previousPeriod }
        });
        
        const previousPeriodRequests = await requestsCollection.countDocuments({
            submissionDate: { 
                $gte: new Date(previousPeriod.getTime() - 30 * 24 * 60 * 60 * 1000),
                $lt: previousPeriod
            }
        });

        const totalTrend = previousPeriodRequests === 0 ? 0 :
            Math.round(((currentPeriodRequests - previousPeriodRequests) / previousPeriodRequests) * 100);

        res.json({
            totalRequests,
            pendingRequests,
            completedToday,
            activeUsers,
            totalTrend,
            pendingTrend: 0, // You can implement more detailed trend calculations if needed
            completedTrend: 0,
            usersTrend: 0
        });
    } catch (error) {
        console.error('Error fetching admin statistics:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API to get chart data for admin dashboard
app.get('/api/admin/chart-data', ensureAuthenticated, ensureAdmin, async (req, res) => {
    try {
        const requestsCollection = db.collection('requests');
        
        // Aggregate data for Requests by Status (Doughnut Chart)
        const statusAggregation = await requestsCollection.aggregate([
            { $group: { _id: '$status', count: { $sum: 1 } } }
        ]).toArray();
        const statusCounts = statusAggregation.reduce((acc, item) => {
            acc[item._id] = item.count;
            return acc;
        }, {});

        // Aggregate data for Requests by Service Type (Pie Chart)
        const serviceAggregation = await requestsCollection.aggregate([
            { $group: { _id: '$serviceType', count: { $sum: 1 } } }
        ]).toArray();
        const serviceCounts = serviceAggregation.reduce((acc, item) => {
            acc[item._id] = item.count;
            return acc;
        }, {});

        // Aggregate data for Service Trends Over Time (Multi-line Chart)
        const trendsAggregation = await requestsCollection.aggregate([
            {
                $group: {
                    _id: {
                        date: { $dateToString: { format: "%Y-%m-%d", date: "$submissionDate" } },
                        serviceType: "$serviceType"
                    },
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { "_id.date": 1, "_id.serviceType": 1 }
            }
        ]).toArray();

        // Transform aggregated data for Chart.js multi-line chart
        const dates = [...new Set(trendsAggregation.map(item => item._id.date))].sort();
        const serviceTypes = [...new Set(trendsAggregation.map(item => item._id.serviceType))];

        const datasets = serviceTypes.map(serviceType => {
            const data = dates.map(date => {
                const entry = trendsAggregation.find(item => item._id.date === date && item._id.serviceType === serviceType);
                return entry ? entry.count : 0;
            });
            return {
                label: serviceType.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase()), // Format serviceType for label
                data: data,
                fill: false,
                tension: 0.1 // Smooth curves
            };
        });

        res.json({
            statusCounts,
            serviceCounts,
            trends: { labels: dates, datasets: datasets }
        });

    } catch (error) {
        console.error('Error fetching chart data:', error);
        res.status(500).json({ message: 'Error fetching chart data', error: error.message });
    }
});

// Admin requests endpoint
app.get('/api/admin/requests', ensureAuthenticated, ensureAdmin, async (req, res) => {
    try {
        const { status, service, dateFrom, dateTo, search } = req.query;
        const query = {};

        if (status && status !== 'all') {
            query.status = status;
        }

        if (service && service !== 'all') {
            query.serviceType = service;
        }

        if (dateFrom || dateTo) {
            query.submissionDate = {};
            if (dateFrom) {
                const fromDate = new Date(dateFrom);
                fromDate.setHours(0, 0, 0, 0);
                query.submissionDate.$gte = fromDate;
            }
            if (dateTo) {
                const toDate = new Date(dateTo);
                toDate.setHours(23, 59, 59, 999);
                query.submissionDate.$lte = toDate;
            }
        }

        if (search) {
            // Case-insensitive search across relevant fields
            const searchRegex = new RegExp(search, 'i');
            query.$or = [
                { 'formData.fullName': searchRegex },
                { 'formData.email': searchRegex },
                { 'formData.lastname': searchRegex },
                { 'formData.firstname': searchRegex },
                { serviceType: searchRegex },
                { status: searchRegex },
                { _id: ObjectId.isValid(search) ? new ObjectId(search) : null } // Allow searching by _id if valid
            ].filter(Boolean); // Remove null if ObjectId.isValid returns false
        }

        const requestsCollection = db.collection('requests');
        const requests = await requestsCollection.find(query, {
            projection: {
                _id: 1,
                userId: 1,
                clientName: 1,
                serviceType: 1,
                submissionDate: 1,
                status: 1,
                formData: 1,
                notes: 1,
                lastUpdated: 1
            }
        }).toArray();

        console.log('[SERVER] Sending requests to frontend. Sample _id:', requests.length > 0 ? requests[0]._id : 'No requests');

        res.json(requests);
    } catch (error) {
        console.error('Error fetching admin requests:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// API to get a single request by requestId for admin dashboard
app.get('/api/admin/requests/:id', ensureAuthenticated, ensureAdmin, async (req, res) => {
    const { id } = req.params;
    console.log(`[ADMIN API] Received request for _id: ${id}`);

    // Validate _id format (MongoDB ObjectId)
    if (!ObjectId.isValid(id)) {
        console.error(`[ADMIN API] Invalid requestId format: ${id}`);
        return res.status(400).json({ message: "Invalid Request ID format." });
    }

    try {
        if (!db) {
            console.error("Database not connected for /api/admin/requests/:id.");
            return res.status(500).json({ message: "Database not available." });
        }

        const requestsCollection = db.collection('requests');
        const query = { _id: new ObjectId(id) };
        console.log(`[ADMIN API] Querying database with:`, query);

        const request = await requestsCollection.findOne(
            query,
            { 
                projection: { 
                    _id: 1, 
                    userId: 1, 
                    serviceType: 1, 
                    submissionDate: 1, 
                    status: 1, 
                    formData: 1, 
                    notes: 1, 
                    lastUpdated: 1 
                } 
            }
        );

        if (!request) {
            console.warn(`[ADMIN API] Request with ID ${id} not found.`);
            return res.status(404).json({ message: "Request not found." });
        }

        console.log(`[ADMIN API] Found request ${id}:`, JSON.stringify(request, null, 2));
        res.json(request);
    } catch (error) {
        console.error(`[ADMIN API] Error fetching request ${id}:`, error);
        res.status(500).json({ message: "Failed to fetch request details." });
    }
});

// API to update request status (for admin dashboard)
app.patch('/api/admin/requests/:id/status', ensureAuthenticated, ensureAdmin, async (req, res) => {
    if (!db) {
        console.error("Database not connected for updating request status.");
        return res.status(500).json({ message: "Database not available." });
    }
    const { id } = req.params;
    const { status: newStatus, notes } = req.body;
    console.log('PATCH /api/admin/requests/:id/status', { id, newStatus, notes }); // Log incoming data
    console.log('req.body:', req.body); // Log the entire request body
    if (!id || !ObjectId.isValid(id)) {
        console.error('Invalid or missing request ID:', id);
        return res.status(400).json({ message: "Invalid Request ID format." });
    }
    if (!newStatus) {
        console.error('Missing newStatus in request body');
        return res.status(400).json({ message: "New status is required." });
    }
    const requestsCollection = db.collection('requests');

    try {
        const objectId = new ObjectId(id); // Convert string ID to ObjectId
        const request = await requestsCollection.findOne({ _id: objectId });

        if (!request) {
            console.error("Request not found for id:", id);
            return res.status(404).json({ message: "Request not found." });
        }

        const oldStatus = request.status; // Get old status before update

        const updateResult = await requestsCollection.updateOne(
            { _id: objectId },
            { 
                $set: { 
                    status: newStatus,
                    notes: notes || request.notes, // Update notes or keep existing if not provided
                    lastUpdated: new Date() // Update last updated timestamp
                }
            }
        );
        console.log("updateResult:", updateResult); // Log update result

        if (updateResult.matchedCount === 0) {
            console.error("Update matched no document for id:", id);
            return res.status(404).json({ message: "Request not found or no changes made." });
        }

        if (updateResult.modifiedCount === 0) {
            console.log("No change (status already " + newStatus + ") for id:", id);
            return res.status(200).json({ message: "Request status is already " + newStatus, requestId: id });
        }
        
        // Send email notification to client if status changed
        if (oldStatus !== newStatus) {
            if (request.email) { // Ensure request.email exists
                await emailAdminOnStatusChange(id, request.clientName, request.serviceType, oldStatus, newStatus, request.email);
            } else {
                console.warn(`Email not available for request ID ${id}. Skipping email notification.`);
            }
        }

        res.json({ message: `Request ${id} status updated to ${newStatus} successfully!`, requestId: id });
    } catch (error) {
        console.error("Error updating request status:", error);
        if (error.name === 'BSONTypeError') { // Catch invalid ObjectId format
            return res.status(400).json({ message: "Invalid Request ID format." });
        }
        res.status(500).json({ message: "Failed to update request status." });
    }
});

// API to delete a request (for admin dashboard)
app.delete('/api/admin/requests/:id', ensureAuthenticated, ensureAdmin, async (req, res) => {
    if (!db) {
        console.error("Database not connected for deleting request.");
        return res.status(500).json({ message: "Database not available." });
    }
    const { id } = req.params;

    console.log(`[DELETE API] Received request to delete ID: ${id}`);

    try {
        const objectId = new ObjectId(id); // Convert string ID to ObjectId
        console.log(`[DELETE API] Converted to ObjectId: ${objectId}`);
        const requestsCollection = db.collection('requests');
        const deleteResult = await requestsCollection.deleteOne({ _id: objectId });

        console.log(`[DELETE API] Delete result:`, deleteResult);

        if (deleteResult.deletedCount === 0) {
            return res.status(404).json({ message: "Request not found." });
        }

        res.json({ message: `Request ${id} deleted successfully!` });
    } catch (error) {
        console.error("Error deleting request:", error);
        if (error.name === 'BSONTypeError') {
            return res.status(400).json({ message: "Invalid Request ID format." });
        }
        res.status(500).json({ message: "Failed to delete request." });
    }
});

// Helper function to format form data into an HTML table for modal display
function formatModalFormData(formData) {
    let html = '<table class="modal-form-data-table">';
    for (const key in formData) {
        if (Object.hasOwnProperty.call(formData, key)) {
            const formattedKey = key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
            let value = formData[key];

            if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                value = '<pre>' + JSON.stringify(value, null, 2) + '</pre>';
            } else if (value === '' || value === null || value === undefined) {
                value = '<em>Not provided</em>';
            }
            html += `<tr><th>${formattedKey}:</th><td>${value}</td></tr>`;
        }
    }
    html += '</table>';
    return html;
}

// Update the connectToMongo function to use Mongoose
async function connectToMongo() {
  try {
    await mongoose.connect(uri);
    db = mongoose.connection.db;
    console.log(`Connected to MongoDB database: ${mongoose.connection.name} successfully!`);
  } catch (error) {
    console.error("Could not connect to MongoDB:", error);
    process.exit(1); // Exit if DB connection fails
  }
}

// Start server after connecting to MongoDB
connectToMongo().then(() => {
    // Ensure static files are served after all API routes are defined
    app.use(express.static(path.join(__dirname)));
    app.get('*', (req, res) => {
        res.status(404).send('404 Not Found');
    });

    // Create server with error handling
    const server = app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    }).on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`Port ${PORT} is already in use. Please try the following:`);
            console.error('1. Close any other applications using this port');
            console.error('2. Wait a few moments and try again');
            console.error('3. Or use a different port by setting the PORT environment variable');
            process.exit(1);
        } else {
            console.error('Error starting server:', err);
            process.exit(1);
        }
    });

    // Handle server shutdown gracefully
    process.on('SIGTERM', () => {
        console.log('SIGTERM signal received: closing HTTP server');
        server.close(() => {
            console.log('HTTP server closed');
            mongoose.connection.close(false, () => {
                console.log('MongoDB connection closed');
                process.exit(0);
            });
        });
    });
});

// Add error handling middleware for JSON parsing
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        console.error('JSON Parse Error:', err);
        return res.status(400).json({ message: 'Invalid JSON in request body' });
    }
    next();
});

// Add a catch-all error handler
app.use((err, req, res, next) => {
    console.error('Global error handler caught:', err);
    res.status(500).json({
        message: "An error occurred processing your request",
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// Add input validation middleware
const validateFormData = (req, res, next) => {
    const formData = req.body;
    if (!formData || typeof formData !== 'object') {
        return res.status(400).json({ message: 'Invalid form data format' });
    }
    // Add more specific validation based on form type
    next();
};

// Apply validation middleware to form submission endpoints
app.post('/api/psa-birth', ensureAuthenticated, validateFormData, async (req, res) => {
    console.log("PSA Birth form submission received");
    const formData = req.body;
    const serviceType = "PSA Birth Certificate";
    const userId = req.user._id;
    const clientName = req.user.name || req.user.email || "Unknown";
    try {
        const newId = await saveRequest(userId, serviceType, formData, clientName);
        await sendFormEmail(serviceType, { ...formData, _id: newId, email: req.user.email, name: clientName });
        res.json({ message: "PSA Birth form submitted successfully!", requestId: newId });
    } catch (error) {
        console.error("Error handling PSA Birth form submission:", error);
        res.status(500).json({ message: "Failed to submit PSA Birth form." });
    }
});

// Add security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});
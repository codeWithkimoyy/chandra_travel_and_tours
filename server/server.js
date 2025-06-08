const express = require('express');
const cors = require('cors');
const { sendFormSubmissionEmail } = require('./email');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());

// Authentication middleware
const authenticateUser = async (req, res, next) => {
    try {
        const authResponse = await fetch('/api/auth/status', {
            credentials: 'include'
        });
        const authData = await authResponse.json();
        
        if (!authData.authenticated) {
            return res.status(401).json({ 
                code: 'SESSION_INVALID',
                message: 'Please log in to submit forms' 
            });
        }
        
        // Add user info to request
        req.user = {
            email: authData.user.email,
            name: authData.user.name
        };
        
        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(500).json({ message: 'Authentication error' });
    }
};

// Form submission endpoints
app.post('/api/passport', authenticateUser, async (req, res) => {
    try {
        const formData = req.body;
        const userInfo = req.user;
        
        // Send email
        await sendFormSubmissionEmail(formData, userInfo, 'Passport Appointment');
        
        // Generate a unique request ID
        const requestId = 'PASSPORT-' + Date.now();
        
        res.json({
            success: true,
            message: 'Passport appointment form submitted successfully',
            requestId
        });
    } catch (error) {
        console.error('Passport form submission error:', error);
        res.status(500).json({ 
            message: 'Error submitting passport appointment form' 
        });
    }
});

// Add similar endpoints for other forms...

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 
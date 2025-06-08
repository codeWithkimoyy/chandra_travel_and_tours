const nodemailer = require('nodemailer');

// Create a transporter using Gmail
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // Your Gmail address
        pass: process.env.EMAIL_PASS  // Your Gmail app password
    }
});

// Function to send form submission emails
async function sendFormSubmissionEmail(formData, userInfo, formType) {
    const { email: userEmail, name: userName } = userInfo;
    
    // Format the form data into a readable HTML table
    const formDataHtml = Object.entries(formData)
        .map(([key, value]) => `<tr><td><strong>${key}:</strong></td><td>${value}</td></tr>`)
        .join('');

    const mailOptions = {
        from: `"${userName}" <${userEmail}>`,
        to: 'janely193.jc@gmail.com, cutamorakim15@gmail.com', // Admin email addresses
        subject: `New ${formType} Form Submission`,
        html: `
            <h2>New ${formType} Form Submission</h2>
            <p><strong>Submitted by:</strong> ${userName} (${userEmail})</p>
            <p><strong>Submission Date:</strong> ${new Date().toLocaleString()}</p>
            <table border="1" cellpadding="5" cellspacing="0">
                ${formDataHtml}
            </table>
        `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:', info.messageId);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

module.exports = {
    sendFormSubmissionEmail
}; 
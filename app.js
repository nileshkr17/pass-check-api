const express = require('express');
const zxcvbn = require('zxcvbn');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.urlencoded({ extended: true })); // Middleware for form data
app.use(express.json()); // Middleware for JSON requests

// Serve the HTML page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Helper function to get the SHA-1 hash of the password
const sha1 = (password) => {
  return crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
};

// Helper function to check if password is in the Pwned Passwords database
const checkPwnedPassword = async (password) => {
  console.log(password);
  const hashedPassword = sha1(password);
  const prefix = hashedPassword.slice(0, 5);
  const suffix = hashedPassword.slice(5);

  try {
    const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`);
    const lines = response.data.split('\n');
    for (let line of lines) {
      const [hashSuffix, count] = line.split(':');
      if (hashSuffix === suffix) {
        return parseInt(count, 10); // Return the breach count if found
      }
    }
    return 0;
  } catch (error) {
    console.error('Error checking pwned password:', error);
    return -1;
  }
};

// API to handle password check via form submission
app.post('/check-password', async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.send('Password is required');
  }

  // Use zxcvbn to evaluate the password strength
  const evaluation = zxcvbn(password);

  // Check if the password has been breached
  const breachCount = await checkPwnedPassword(password);

  if (breachCount === -1) {
    return res.send('Error checking pwned passwords');
  }

  // Prepare the result to display on the HTML page
  const result = `
    <h2>Password Check Results</h2>
    <p>Score (0-4): ${evaluation.score}</p>
    <p>Feedback: ${evaluation.feedback.suggestions.join(', ') || 'No suggestions'}</p>
    <p>Estimated Crack Time: ${evaluation.crack_times_display.offline_fast_hashing_1e10_per_second}</p>
    <p>${breachCount > 0 ? `This password has been found in ${breachCount} breaches.` : 'This password is safe from known breaches.'}</p>
    <br>
    <a href="/">Try Another Password</a>
  `;

  res.send(result);
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

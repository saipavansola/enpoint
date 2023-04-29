const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors=require("cors")
const saltRounds = 10;

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.listen(3000);

// Create Database named 'Bank'
const db = new sqlite3.Database('Bank.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the Bank database.');
});

// Create Users table
db.run(`CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    isBanker BOOLEAN NOT NULL DEFAULT 0
)`);

// Create Accounts table
db.run(`CREATE TABLE IF NOT EXISTS Accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    amount REAL NOT NULL DEFAULT 0,
    transactionType TEXT NOT NULL,
    FOREIGN KEY (userId) REFERENCES Users(id)
)`);

// Register User
app.post('/register', async (req, res) => {
  const { email, password, isBanker } = req.body;

  const hash = await bcrypt.hash(password, saltRounds);
  db.run(`INSERT INTO Users (email, password, isBanker) VALUES (?, ?, ?)`, [email, hash, isBanker], (err) => {
    if (err) {
      res.status(500).json({ message: 'Error registering user' });
      return console.error(err.message);
    }
    res.status(200).json({ message: 'User registered successfully' });
  });
});

// Login User
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM Users WHERE email = ?`, [email], async (err, user) => {
    if (err) {
      res.status(500).json({ message: 'Error logging in' });
      return console.error(err.message);
    }
    if (!user) {
      res.status(401).json({ message: 'Invalid email or password' });
      return;
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      res.status(401).json({ message: 'Invalid email or password' });
      return;
    }

    const accessToken = jwt.sign({ userId: user.id, email: user.email }, process.env.ACCESS_TOKEN_SECRET);
    res.status(200).json({ accessToken });
  });
});

// Middleware to authenticate user
function authenticateUser(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ message: 'Access token missing' });
    return;
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      res.status(403).json({ message: 'Invalid access token' });
      return console.error(err.message);
    }
    req.user = user;
    next();
  });
}

// Get Transactions
// Transactions Page
app.get('/transactions', async (req, res) => {
    try {
      // get the user id from the access token in the header
      const userId = getUserIdFromToken(req.headers.authorization);
  
      // get the user's account
      const account = await db.get('SELECT * FROM Accounts WHERE user_id = ?', userId);
  
      res.send(`
        <html>
          <head>
            <title>Transactions</title>
          </head>
          <body>
            <h1>Transactions</h1>
            <p>Balance: ${account.balance}</p>
            <button onclick="showPopup('deposit')">Deposit</button>
            <button onclick="showPopup('withdraw')">Withdraw</button>
            
            <div id="deposit-popup" style="display: none">
              <p>Available Balance: ${account.balance}</p>
              <input type="number" id="deposit-amount">
              <button onclick="deposit()">Deposit</button>
            </div>
            
            <div id="withdraw-popup" style="display: none">
              <p>Available Balance: ${account.balance}</p>
              <input type="number" id="withdraw-amount">
              <button onclick="withdraw()">Withdraw</button>
            </div>
            
            <script>
              function showPopup(type) {
                if (type === 'deposit') {
                  document.getElementById('deposit-popup').style.display = 'block';
                } else if (type === 'withdraw') {
                  document.getElementById('withdraw-popup').style.display = 'block';
                }
              }
              
              function deposit() {
                const amount = document.getElementById('deposit-amount').value;
                fetch('/deposit', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'Authorization': '${req.headers.authorization}'
                  },
                  body: JSON.stringify({ amount })
                })
                .then(() => {
                  location.reload();
                });
              }
              
              function withdraw() {
                const amount = document.getElementById('withdraw-amount').value;
                fetch('/withdraw', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'Authorization': '${req.headers.authorization}'
                  },
                  body: JSON.stringify({ amount })
                })
                .then(() => {
                  location.reload();
                });
              }
            </script>
          </body>
        </html>
      `);
    } catch (error) {
      console.log(error);
      res.status(500).send('Internal Server Error');
    }
  });
  

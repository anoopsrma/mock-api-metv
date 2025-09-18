require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const multer = require('multer');
const { createClient } = require('@libsql/client');

const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const upload = multer();

// JWT Secret (use env var in production)
const JWT_SECRET = 'your_jwt_secret_key';

// Create Turso client
const db = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
});

// Create users table
async function createUserTable() {
    await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      token TEXT DEFAULT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
    console.log('User table ready');
}

// Register user
app.post('/api/v1/register', upload.none(), async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ status: false, error: 'Missing fields' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.execute({
            sql: `INSERT INTO users (username, password) VALUES (?, ?)`,
            args: [username, hashedPassword],
        });

        return res.status(201).json({
            status: true,
            message: 'User registered successfully.',
        });
    } catch (err) {
        if (err.message.includes('UNIQUE')) {
            return res.status(409).json({
                status: false,
                error: 'User already exists!',
            });
        }
        console.error('❌ Error:', err.message);
        return res.status(500).json({
            status: false,
            error: 'Internal server error',
        });
    }
});

// Login
app.post('/api/v1/login', upload.none(), async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password)
        return res.status(400).json({ status: false, error: 'Missing credentials' });

    try {
        // Fetch user from DB
        const result = await db.execute({
            sql: `SELECT * FROM users WHERE username = ?`,
            args: [username],
        });

        const user = result.rows[0];

        if (!user)
            return res.status(401).json({ status: false, error: 'Invalid username or password' });

        // Compare passwords
        const match = await bcrypt.compare(password, user.password);
        if (!match)
            return res.status(401).json({ status: false, error: 'Invalid username or password' });

        // Generate JWT
        const token = jwt.sign(
            { id: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '1d' }
        );

        // Store token in DB (optional)
        await db.execute({
            sql: `UPDATE users SET token = ? WHERE id = ?`,
            args: [token, user.id],
        });

        return res.status(200).json({
            status: true,
            data: {
                "access_token": token,
                "name": "Lorem Ipsum",
                "email": "lorem@ipsum.com",
                "phone": "1234567890"
            }
        });

    } catch (err) {
        console.error('❌ Login error:', err.message);
        return res.status(500).json({ status: false, error: 'Server error' });
    }
});

app.post('/api/v1/refresh', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ status: false, error: 'Missing or invalid token' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return res.status(200).json({ status: true, data: { access_token: token } });
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            try {
                const decoded = jwt.decode(token, { complete: true });
                const exp = decoded.payload.exp;
                const now = Math.floor(Date.now() / 1000);
                const secondsSinceExpired = now - exp;
                if (secondsSinceExpired > 86400) {
                    return res.status(401).json({ status: false, error: 'Token expired more than 1 day ago' });
                }
                // Create a new access token
                const newAccessToken = jwt.sign(
                    {
                        id: decoded.payload.id,
                        username: decoded.payload.username
                    },
                    JWT_SECRET,
                    { expiresIn: '1d' }
                );
                return res.status(200).json({
                    status: true,
                    data: {
                        access_token: newAccessToken
                    }
                });
            } catch (decodeErr) {
                return res.status(400).json({ status: false, error: 'Invalid token structure' });
            }
        }

        return res.status(400).json({ status: false, error: 'Invalid token' });
    }
});


// Forgot Password
app.post('/api/v1/password/forgot', upload.none(), async (req, res) => {
    const { username } = req.body;
    try {
        const result = await db.execute({
            sql: `SELECT * FROM users WHERE username = ?`,
            args: [username],
        });

        const user = result.rows[0];
        if (!user) {
            return res.status(404).json({
                status: false,
                error: 'User not found!',
            });
        }
        // Generate and store reset token
        const resetToken = Math.floor(100000 + Math.random() * 900000).toString(); // e.g., "123456"
        await db.execute({
            sql: `UPDATE users SET token = ? WHERE username = ?`,
            args: [resetToken, username],
        });
        // Simulate sending token
        console.log(`🔐 Reset token for ${username}: ${resetToken}`);
        res.status(200).json({
            status: true,
            message: 'Password reset code has been sent (simulated)',
        });
    } catch (err) {
        console.error('❌ Forgot password error:', err.message);
        res.status(500).json({
            status: false,
            error: 'Internal server error',
        });
    }
});


app.post('/api/v1/password/reset', upload.none(), async (req, res) => {
    const { username, token, new_password } = req.body;

    try {
        const result = await db.execute({
            sql: `SELECT * FROM users WHERE username = ?`,
            args: [username],
        });

        const user = result.rows[0];
        if (!user) {
            return res.status(404).json({
                status: false,
                error: 'User not found!',
            });
        }
        console.log(token)
        if (!user.token || token !== "123456") {
            return res.status(422).json({
                status: false,
                error: 'Invalid or expired reset token',
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(new_password, 10);

        // Update password and clear token
        await db.execute({
            sql: `UPDATE users SET password = ?, token = NULL WHERE username = ?`,
            args: [hashedPassword, username],
        });

        res.status(200).json({
            status: true,
            message: 'Password has been reset successfully',
        });
    } catch (err) {
        console.error('❌ Reset password error:', err.message);
        res.status(500).json({
            status: false,
            error: 'Internal server error',
        });
    }
});

app.post('/api/v1/email/verify', upload.none(), async (req, res) => {
    const { username, token } = req.body;

    try {
        const result = await db.execute({
            sql: `SELECT * FROM users WHERE username = ?`,
            args: [username],
        });

        const user = result.rows[0];
        if (!user) {
            return res.status(404).json({
                status: false,
                error: 'User not found!',
            });
        }
        console.log(token)
        if (!user.token || token !== "123456") {
            return res.status(422).json({
                status: false,
                error: 'Invalid or expired token',
            });
        }

        res.status(200).json({
            status: true,
            message: 'Email has been verified successfully',
        });
    } catch (err) {
        console.error('❌ Email verify error:', err.message);
        res.status(500).json({
            status: false,
            error: 'Internal server error',
        });
    }
});

app.post('/api/v1/password/change', upload.none(), async (req, res) => {
    const { old_password, new_password } = req.body;
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            status: false,
            message: 'Unauthorized: Bearer token missing or malformed'
        });
    }

    try {
        const result = await db.execute({
            sql: `SELECT * FROM users WHERE username = ?`,
            args: [username],
        });

        const user = result.rows[0];
        if (!user) {
            return res.status(404).json({
                status: false,
                error: 'User not found!',
            });
        }

        const isMatch = await bcrypt.compare(old_password, user.password);
        if (!isMatch) {
            res.status(200).json({
                status: true,
                message: 'Invalid password,',
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(new_password, 10);

        // Update password and clear token
        await db.execute({
            sql: `UPDATE users SET password = ?, token = NULL WHERE username = ?`,
            args: [hashedPassword, username],
        });

        res.status(200).json({
            status: true,
            message: 'Password has been reset successfully',
        });
    } catch (err) {
        console.error('❌ change password error:', err.message);
        res.status(500).json({
            status: false,
            error: 'Internal server error',
        });
    }
});

// Delete user
app.delete('/api/v1/user/delete', upload.none(), async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ status: false, error: 'Missing fields' });

    try {
        // Check if user exists
        const [user] = await db.execute({
            sql: `SELECT password FROM users WHERE username = ?`,
            args: [username],
        });

        if (!user || user.length === 0) {
            return res.status(404).json({
                status: false,
                error: 'User not found',
            });
        }

        const isPasswordValid = await bcrypt.compare(password, user[0].password);
        if (!isPasswordValid) {
            return res.status(401).json({
                status: false,
                error: 'Invalid password',
            });
        }

        // Delete user
        await db.execute({
            sql: `DELETE FROM users WHERE username = ?`,
            args: [username],
        });

        return res.status(200).json({
            status: true,
            message: 'User deleted successfully.',
        });

    } catch (err) {
        console.error('❌ Error:', err.message);
        return res.status(500).json({
            status: false,
            error: 'Internal server error',
        });
    }
});

app.get('/api/v1/config', (req, res) => {
    res.json({
        status: true,
        data: {
            terms_and_conditions: "/api/v1/policy/terms",
            privacy_policy: "/api/v1/policy/privacy",
            logo: "https://picsum.photos/600/400",
            forgot_password: {
                label: "Forgot Password",
                route: "/api/v1/password/forgot",
                form: [
                    {
                        label: "Email", key: "username", data_type: "string"
                    },
                ]
            },
            reset_password: {
                label: "Reset Password",
                route: "/api/v1/password/reset",
                form: [
                    {
                        label: "Email", key: "username", data_type: "string"
                    },
                    {
                        label: "Password", key: "new_password", data_type: "string"
                    },
                    {
                        label: "Token", key: "token", data_type: "string"
                    },
                ]
            },
            email_verify: {
                label: "Email Verify",
                route: "/api/v1/email/verify",
                form: [
                    {
                        label: "Email", key: "username", data_type: "string"
                    },
                    {
                        label: "Token", key: "token", data_type: "string"
                    },
                ]
            },
            version_check: {
                label: "Version Check",
                route: "/api/v1/version/check",
                query: [
                    {
                        label: "Version", key: "version", data_type: "string"
                    }
                ]
            },
            login: [
                {
                    label: "Normal Login",
                    key: "normal",
                    data_type: "auth",
                    route: "/api/v1/login",
                    form: [
                        {
                            label: "Username", key: "username", data_type: "string"
                        },
                        {
                            label: "Password", key: "password", data_type: "string"
                        },
                    ],
                },
                {
                    label: "Facebook Login",
                    key: "facebook",
                    data_type: "oauth",
                    route: "/api/v1/login/facebook",
                    form: []
                },
                {
                    label: "Google Login",
                    key: "google",
                    data_type: "oauth",
                    route: "/api/v1/login/google",
                    form: []
                }
            ],
            user_delete: {
                label: "Delete User",
                route: "/api/v1/user/delete",
                form: [
                    {
                        label: "Username", key: "username", data_type: "string"
                    },
                    {
                        label: "Password", key: "password", data_type: "string"
                    },
                ],
            },
            register: {
                "route": "/api/v1/register",
                "form": [
                    {
                        label: "First Name", key: "first_name", data_type: "string"
                    },
                    {
                        label: "Last Name", key: "last_name", data_type: "string"
                    },
                    {
                        label: "Email", key: "email", data_type: "string"
                    },
                    {
                        label: "Password", key: "password", data_type: "string"
                    },
                    {
                        label: "Confirm Password", key: "confirm_password", data_type: "string"
                    },
                    {
                        label: "Phone Number", key: "phone", data_type: "string"
                    },
                    {
                        label: "Gender",
                        key: "gender",
                        data_type: "enum",
                        options: [
                            "Male",
                            "Female",
                            "Other"
                        ]
                    }
                ]
            },
            home: {
                label: "Home",
                route: "/api/v1/home",
            },
            search: {
                label: "Terms",
                key: "search",
                route: "/api/v1/search",
            },
        }
    });
});

// Home
app.get('/api/v1/home', (req, res) => {
    const now = new Date();
    const isoTime = now.toISOString().split('.')[0] + 'Z'; 
    res.json({
        "status": true,
        "data": {
            "categories": [
                {
                    "name": "First",
                    "route": "",
                    "list": [
                        {
                            "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                            "title": "The Flash",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.2",
                            "release_year": 2023,
                            "is_live": true,
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Action",
                                "Adventure"
                            ],
                            "epg": "api/v1/epgs/f47ac10b-58cc-4372-a567-0e02b2c3d479"
                        }
                    ]
                },
                {
                    "name": "Epg",
                    "route": "/api/v1/epgs/:channelId",
                    "list": [
                        {
                            "id": "epg_000",
                            "title": "Planet Earth: Ice Worlds",
                            "description": "Explore the icy habitats of polar regions and the species that survive there.",
                            "date": isoTime,
                            "start": "2025-09-18T00:00:00Z",
                            "end": "2025-09-18T01:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Nature",
                                "Documentary"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_001",
                            "title": "Secrets of the Zoo",
                            "description": "Go behind the scenes at one of the largest zoos in the world.",
                            "date": isoTime,
                            "start": "2025-09-18T01:00:00Z",
                            "end": "2025-09-18T02:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Animal",
                                "Reality"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_002",
                            "title": "Engineering Marvels",
                            "description": "Discover how modern marvels are constructed from start to finish.",
                            "date": isoTime,
                            "start": "2025-09-18T02:00:00Z",
                            "end": "2025-09-18T03:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Science",
                                "Engineering"
                            ],
                            "rating": "7.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_003",
                            "title": "Wildlife SOS",
                            "description": "Follow rescue teams helping injured or endangered wild animals.",
                            "date": isoTime,
                            "start": "2025-09-18T03:00:00Z",
                            "end": "2025-09-18T04:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Wildlife",
                                "Rescue"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_004",
                            "title": "Mega Factories",
                            "description": "A look inside the world's most advanced production facilities.",
                            "date": isoTime,
                            "start": "2025-09-18T04:00:00Z",
                            "end": "2025-09-18T05:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Technology",
                                "Industry"
                            ],
                            "rating": "7.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_005",
                            "title": "Air Crash Investigation",
                            "description": "Explore the causes of major aviation disasters.",
                            "date": isoTime,
                            "start": "2025-09-18T05:00:00Z",
                            "end": "2025-09-18T06:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Investigation",
                                "Documentary"
                            ],
                            "rating": "PG-13",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_006",
                            "title": "Locked Up Abroad",
                            "description": "Real stories of people caught smuggling drugs or breaking laws overseas.",
                            "date": isoTime,
                            "start": "2025-09-18T06:00:00Z",
                            "end": "2025-09-18T07:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Crime",
                                "Drama"
                            ],
                            "rating": "TV-14",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_007",
                            "title": "Explorer",
                            "description": "Adventures from the frontiers of science and discovery.",
                            "date": isoTime,
                            "start": "2025-09-18T07:00:00Z",
                            "end": "2025-09-18T08:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Adventure",
                                "Science"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_008",
                            "title": "Brain Games",
                            "description": "Mind-bending challenges that explore the brain’s inner workings.",
                            "date": isoTime,
                            "start": "2025-09-18T08:00:00Z",
                            "end": "2025-09-18T09:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Science",
                                "Education"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_009",
                            "title": "Cosmos: A Spacetime Odyssey",
                            "description": "A journey through the universe and the laws of nature.",
                            "date": isoTime,
                            "start": "2025-09-18T09:00:00Z",
                            "end": "2025-09-18T10:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Science",
                                "Space"
                            ],
                            "rating": "7.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_010",
                            "title": "Running Wild",
                            "description": "Survival experts take celebrities into the wild.",
                            "date": isoTime,
                            "start": "2025-09-18T10:00:00Z",
                            "end": "2025-09-18T11:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Adventure",
                                "Reality"
                            ],
                            "rating": "7.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_011",
                            "title": "Animal Fight Club",
                            "description": "Nature’s most aggressive battles between animals.",
                            "date": isoTime,
                            "start": "2025-09-18T11:00:00Z",
                            "end": "2025-09-18T12:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Wildlife",
                                "Action"
                            ],
                            "rating": "TV-14",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_012",
                            "title": "Drain the Oceans",
                            "description": "3D scanning reveals secrets hidden beneath the oceans.",
                            "date": isoTime,
                            "start": "2025-09-18T12:00:00Z",
                            "end": "2025-09-18T13:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Science",
                                "Marine"
                            ],
                            "rating": "7.5",
                            "is_onair": true,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_013",
                            "title": "Lost Cities",
                            "description": "Explore ancient ruins and civilizations with modern technology.",
                            "date": isoTime,
                            "start": "2025-09-18T13:00:00Z",
                            "end": "2025-09-18T14:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "History",
                                "Archaeology"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_014",
                            "title": "Mars: Inside SpaceX",
                            "description": "Inside Elon Musk's plan to colonize Mars.",
                            "date": isoTime,
                            "start": "2025-09-18T14:00:00Z",
                            "end": "2025-09-18T15:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Science",
                                "Technology"
                            ],
                            "rating": "7.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_015",
                            "title": "Ultimate Airport Dubai",
                            "description": "Behind the scenes of one of the world's busiest airports.",
                            "date": isoTime,
                            "start": "2025-09-18T15:00:00Z",
                            "end": "2025-09-18T16:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Reality",
                                "Travel"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_016",
                            "title": "Nazi Megastructures",
                            "description": "Exploring Hitler’s massive military infrastructure.",
                            "date": isoTime,
                            "start": "2025-09-18T16:00:00Z",
                            "end": "2025-09-18T17:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "History",
                                "War"
                            ],
                            "rating": "PG-13",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_017",
                            "title": "The Hot Zone",
                            "description": "Docudrama about deadly virus outbreaks.",
                            "date": isoTime,
                            "start": "2025-09-18T17:00:00Z",
                            "end": "2025-09-18T18:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Drama",
                                "Science"
                            ],
                            "rating": "TV-14",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_018",
                            "title": "Mars",
                            "description": "A blend of drama and documentary about the future of Mars exploration.",
                            "date": isoTime,
                            "start": "2025-09-18T18:00:00Z",
                            "end": "2025-09-18T19:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Science Fiction",
                                "Space"
                            ],
                            "rating": "TV-PG",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_019",
                            "title": "The Story of God with Morgan Freeman",
                            "description": "Exploring different cultures’ views on God and spirituality.",
                            "date": isoTime,
                            "start": "2025-09-18T19:00:00Z",
                            "end": "2025-09-18T20:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Religion",
                                "Documentary"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_020",
                            "title": "Science of Stupid",
                            "description": "Funny fails with a scientific explanation.",
                            "date": isoTime,
                            "start": "2025-09-18T20:00:00Z",
                            "end": "2025-09-18T21:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Comedy",
                                "Science"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_021",
                            "title": "Great Migrations",
                            "description": "Witness the planet’s greatest animal migrations.",
                            "date": isoTime,
                            "start": "2025-09-18T21:00:00Z",
                            "end": "2025-09-18T22:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Nature",
                                "Wildlife"
                            ],
                            "rating": "8.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_022",
                            "title": "Explorer: Deep Sea",
                            "description": "Uncovering the mysteries of the deep ocean.",
                            "date": isoTime,
                            "start": "2025-09-18T22:00:00Z",
                            "end": "2025-09-18T23:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Marine",
                                "Science"
                            ],
                            "rating": "7.5",
                            "is_onair": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_023",
                            "title": "The Next Megaquake",
                            "description": "The science and predictions of future large earthquakes.",
                            "date": isoTime,
                            "start": "2025-09-18T23:00:00Z",
                            "end": "2025-09-13T00:00:00Z",
                            "route": "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
                            "genres": [
                                "Science",
                                "Disaster"
                            ],
                            "is_onair": false,
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        }
                    ]
                },
                {
                    "name": "Popular",
                    "route": "/api/v1/movies/popular",
                    "list": [
                        {
                            "id": "d9428888-122b-11e1-b85c-61cd3cbb3210",
                            "title": "The Flash",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.2",
                            "release_year": 2023,
                            "is_live": false,
                            "route": "api/v1/movies/d9428888-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Action",
                                "Adventure"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d9428889-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Avatar: The Way of Water",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.7",
                            "release_year": 2022,
                            "is_live": false,
                            "route": "api/v1/movies/d9428889-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Action",
                                "Sci-Fi"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d9428890-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Barbie",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "7.8",
                            "release_year": 2023,
                            "is_live": false,
                            "route": "api/v1/movies/d9428890-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Comedy",
                                "Adventure"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d9428891-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Oppenheimer",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "9.1",
                            "release_year": 2023,
                            "is_live": false,
                            "route": "api/v1/movies/d9428891-122b-11e1-b85c-61cd3cbb3210",
                            "genres": [
                                "Drama",
                                "History"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d9428892-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Guardians of the Galaxy Vol. 3",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8",
                            "release_year": 2023,
                            "is_live": false,
                            "route": "api/v1/movies/d9428892-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Action",
                                "Sci-Fi"
                            ],
                            "epg": ""
                        }
                    ]
                },
                {
                    "name": "Trending",
                    "route": "/api/v1/movies/trending",
                    "list": [
                        {
                            "id": "d9428893-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Dune: Part Two",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.5",
                            "release_year": 2024,
                            "is_live": false,
                            "route": "api/v1/movies/d9428893-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Sci-Fi",
                                "Adventure"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d9428894-122b-11e1-b85c-61cd3cbb3210",
                            "title": "John Wick: Chapter 4",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.3",
                            "release_year": 2023,
                            "is_live": false,
                            "route": "api/v1/movies/d9428894-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Action",
                                "Thriller"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d9428895-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Spider-Man: Across the Spider-Verse",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "9",
                            "release_year": 2023,
                            "is_live": false,
                            "route": "api/v1/movies/d9428895-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Action",
                                "Animation"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d9428896-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Mission: Impossible – Dead Reckoning",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.4",
                            "release_year": 2023,
                            "is_live": false,
                            "route": "api/v1/movies/d9428896-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Action",
                                "Adventure"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d9428897-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Indiana Jones and the Dial of Destiny",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "7.9",
                            "release_year": 2023,
                            "is_live": false,
                            "route": "api/v1/movies/d9428897-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Adventure",
                                "Action"
                            ],
                            "epg": ""
                        }
                    ]
                },
                {
                    "name": "Top Rated",
                    "route": "/api/v1/movies/top-rated",
                    "list": [
                        {
                            "id": "d9428898-122b-11e1-b85c-61cd3cbb3210",
                            "title": "The Shawshank Redemption",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "9.3",
                            "release_year": 1994,
                            "is_live": false,
                            "route": "api/v1/movies/d9428898-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Drama"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d9428899-122b-11e1-b85c-61cd3cbb3210",
                            "title": "The Godfather",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "9.2",
                            "release_year": 1972,
                            "is_live": false,
                            "route": "api/v1/movies/d9428899-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Crime",
                                "Drama"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d94288a0-122b-11e1-b85c-61cd3cbb3210",
                            "title": "The Dark Knight",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "9",
                            "release_year": 2008,
                            "is_live": false,
                            "route": "api/v1/movies/d94288a0-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Action",
                                "Crime"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d94288a1-122b-11e1-b85c-61cd3cbb3210",
                            "title": "12 Angry Men",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "9",
                            "release_year": 1957,
                            "is_live": false,
                            "route": "api/v1/movies/d94288a1-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Drama"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d94288a2-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Schindler's List",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.9",
                            "release_year": 1993,
                            "is_live": false,
                            "route": "api/v1/movies/d94288a2-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "History",
                                "Drama"
                            ],
                            "epg": ""
                        }
                    ]
                },
                {
                    "name": "Editor Picks",
                    "route": "/api/v1/movies/editor-picks",
                    "list": [
                        {
                            "id": "d94288a3-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Inception",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.8",
                            "release_year": 2010,
                            "is_live": false,
                            "route": "api/v1/movies/d94288a3-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Action",
                                "Sci-Fi"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d94288a4-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Parasite",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.6",
                            "release_year": 2019,
                            "is_live": false,
                            "route": "api/v1/movies/d94288a4-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Thriller",
                                "Drama"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d94288a5-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Interstellar",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.6",
                            "release_year": 2014,
                            "is_live": false,
                            "route": "api/v1/movies/d94288a5-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Sci-Fi",
                                "Adventure"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d94288a6-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Whiplash",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.5",
                            "release_year": 2014,
                            "is_live": false,
                            "route": "api/v1/movies/d94288a6-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Drama",
                                "Music"
                            ],
                            "epg": ""
                        },
                        {
                            "id": "d94288a7-122b-11e1-b85c-61cd3cbb3210",
                            "title": "The Prestige",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.5",
                            "release_year": 2006,
                            "is_live": false,
                            "route": "api/v1/movies/d94288a7-122b-11e1-b85c-61cd3cbb3210/stream",
                            "genres": [
                                "Drama",
                                "Mystery"
                            ],
                            "epg": ""
                        }
                    ]
                }
            ]
        }
    }
    )
})

// Home
app.get('/api/v1/search', (req, res) => {
    const query = req.query.search?.toLowerCase() || '';
    console.log(query)
    const show = {
        id: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        title: "The Flash",
        poster: "https://picsum.photos/600/400",
        rating: "8.2",
        release_year: 2023,
        is_live: true,
        route: "api/v1/movies/f47ac10b-58cc-4372-a567-0e02b2c3d479/stream",
        genres: ["Action", "Adventure"],
        epg: "api/v1/epgs/f47ac10b-58cc-4372-a567-0e02b2c3d479"
    };

    const isMatch = show.title.toLowerCase().includes(query);

    res.json({
        status: true,
        data: isMatch && query ? [show] : []
    });
});

// Stream
app.get('/api/v1/movies/:channelId/stream', (req, res) => {
    // const authHeader = req.headers['authorization'];

    // if (!authHeader || !authHeader.startsWith('Bearer ')) {
    //     return res.status(401).json({
    //         status: false,
    //         message: 'Unauthorized: Bearer token missing or malformed'
    //     });
    // }
    const channelId = req.params.channelId;
    live_url = ''
    dvr_url = ''
    if (channelId != "f47ac10b-58cc-4372-a567-0e02b2c3d479") {
        live_url = "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8"
        dvr_url = "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8"
    } else {
        live_url = "https://ntvedge.truestreamz.com/ntvlive/ntvithari-abr.stream/playlist.m3u8"
        dvr_url = "https://ntvedge.truestreamz.com/ntvlive/ntvithari-abr.stream/playlist_dvr.m3u8"
    }

    res.json({
        status: true,
        data: {
            "price": 5.00,
            "genre": [
                "Action",
                "Comedy"
            ],
            "description": "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.",
            "live_url": live_url,
            "dvr_url": dvr_url,
            "next_program": [
                {
                    "id": "d9428888-122b-11e1-b85c-61cd3cbb3210",
                    "title": "The Flash",
                    "poster": "https://picsum.photos/600/400",
                    "rating": "8.2",
                    "release_year": 2023,
                    "is_live": false,
                    "route": "api/v1/movies/d9428888-122b-11e1-b85c-61cd3cbb3210/stream",
                    "genres": [
                        "Action",
                        "Adventure"
                    ],
                    "epg": ""
                },
                {
                    "id": "d9428889-122b-11e1-b85c-61cd3cbb3210",
                    "title": "Avatar: The Way of Water",
                    "poster": "https://picsum.photos/600/400",
                    "rating": "8.7",
                    "release_year": 2022,
                    "is_live": false,
                    "route": "api/v1/movies/d9428889-122b-11e1-b85c-61cd3cbb3210/stream",
                    "genres": [
                        "Action",
                        "Sci-Fi"
                    ],
                    "epg": ""
                },
                {
                    "id": "d9428890-122b-11e1-b85c-61cd3cbb3210",
                    "title": "Barbie",
                    "poster": "https://picsum.photos/600/400",
                    "rating": "7.8",
                    "release_year": 2023,
                    "is_live": false,
                    "route": "api/v1/movies/d9428890-122b-11e1-b85c-61cd3cbb3210/stream",
                    "genres": [
                        "Comedy",
                        "Adventure"
                    ],
                    "epg": ""
                },
                {
                    "id": "d9428891-122b-11e1-b85c-61cd3cbb3210",
                    "title": "Oppenheimer",
                    "poster": "https://picsum.photos/600/400",
                    "rating": "9.1",
                    "release_year": 2023,
                    "is_live": false,
                    "route": "api/v1/movies/d9428891-122b-11e1-b85c-61cd3cbb3210/stream",
                    "genres": [
                        "Drama",
                        "History"
                    ],
                    "epg": ""
                },
                {
                    "id": "d9428892-122b-11e1-b85c-61cd3cbb3210",
                    "title": "Guardians of the Galaxy Vol. 3",
                    "poster": "https://picsum.photos/600/400",
                    "rating": "8",
                    "release_year": 2023,
                    "is_live": false,
                    "route": "api/v1/movies/d9428892-122b-11e1-b85c-61cd3cbb3210/stream",
                    "genres": [
                        "Action",
                        "Sci-Fi"
                    ],
                    "epg": ""
                }
            ]
        },
    });
});

app.get('/api/v1/version/check', (req, res) => {
    const clientVersion = req.query.version_code || 0;
    const is_maintanence = req.query.is_maintanence || false;
    const latestVersion = 2;
    const forceUpdateVersion = 1;
    const forceUpdate = clientVersion < forceUpdateVersion;
    res.json({
        status: true,
        data: {
            update: clientVersion < latestVersion,
            update_type: forceUpdate ? 'force' : 'normal',
            is_maintanence: is_maintanence ? true : false,
            message: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries"
        }
    });
});

app.get('/api/v1/policy/privacy', (req, res) => {
    res.json({
        status: true,
        data: {
            privacy: `<section class="privacy-body forall"> <h3 class="heading">Privacy Policy</h3> <h4><span id="docs-internal-guid-4d7d11b5-7fff-ac75-13a4-295511e2a44e"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">This Privacy Policy describes how World Tv Go (“we”, “our'' or “us”) collects, uses, and shares your personal information when you use our application (the “App”). Please read this Privacy Policy carefully before downloading, accessing, or using the App.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">Introduction:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">World Tv Go respects your privacy. This Privacy Statement applies to all of our web sites and our other products and services. This Privacy Statement explains what information we collect through the World Tv Go product, how we use that information, and what choices you have. The World Tv Go product contains links to other websites. This Privacy Statement does not apply to the practices of any company or individual that World Tv Go does not control or any websites or services that you link to from the World Tv Go products. You should use caution and review the privacy policies of any websites or services that you visit from ours to learn more about their information practices. Please take a few moments to read this Privacy Statement. By accessing the World Tv Go product, you agree to accept the terms and conditions of this Privacy Statement and are aware that our policies may evolve in the future as indicated below. In the event of a conflict between this Privacy Statement and our Terms of Use, our Terms of Use will be controlled.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">Information We Collect:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">When you use our application, we may collect the following information:</span></p><ol style="margin-bottom: 0px; padding-inline-start: 48px;"><li dir="ltr" style="list-style-type: decimal; font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space: pre;" aria-level="1"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;" role="presentation"><span style="font-size: 12pt; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; text-wrap: wrap;">Personal information: such as your name, email address, phone number, User image (If you log in through facebook and gmail or if you upload it directly)&nbsp; and location.</span></p></li><li dir="ltr" style="list-style-type: decimal; font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space: pre;" aria-level="1"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;" role="presentation"><span style="font-size: 12pt; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; text-wrap: wrap;">Device information: such as the device type, operating system, and version number.</span></p></li><li dir="ltr" style="list-style-type: decimal; font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space: pre;" aria-level="1"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;" role="presentation"><span style="font-size: 12pt; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; text-wrap: wrap;">Usage information: such as your interactions with our application, including the content you access and the features you use.</span></p></li><li dir="ltr" style="list-style-type: decimal; font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space: pre;" aria-level="1"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;" role="presentation"><span style="font-size: 12pt; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; text-wrap: wrap;">Other information: such as your IP address and cookie data.</span></p></li></ol><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">We may collect this information directly from you or through third-party services, such as social media platforms or analytics providers.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">How We Use Your Information:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">We use the information we collect to provide and improve our application and services, to personalize your experience, and to communicate with you. We may also use your information to:</span></p><ol style="margin-bottom: 0px; padding-inline-start: 48px;"><li dir="ltr" style="list-style-type: decimal; font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space: pre;" aria-level="1"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;" role="presentation"><span style="font-size: 12pt; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; text-wrap: wrap;">Analyze and monitor the use of our application and services.</span></p></li><li dir="ltr" style="list-style-type: decimal; font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space: pre;" aria-level="1"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;" role="presentation"><span style="font-size: 12pt; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; text-wrap: wrap;">Detect, prevent, and address technical issues or fraud.</span></p></li><li dir="ltr" style="list-style-type: decimal; font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space: pre;" aria-level="1"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;" role="presentation"><span style="font-size: 12pt; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; text-wrap: wrap;">Comply with legal requirements and protect our rights and interests.</span></p></li><li dir="ltr" style="list-style-type: decimal; font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space: pre;" aria-level="1"><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;" role="presentation"><span style="font-size: 12pt; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; text-wrap: wrap;">Send you promotional materials, updates, and notifications about our application and services.</span></p></li></ol><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;"><span style="width:100px;display:inline-block;position:relative;"></span></span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">How We Protect Your Information:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">We take reasonable and appropriate measures to protect the information we collect from unauthorized access, disclosure, or destruction. We use industry-standard security technologies, such as encryption and firewalls, to safeguard your information. However, please note that no method of transmission over the internet or electronic storage is 100% secure.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">How we Share Your Information:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">We may share your information with third-party service providers who assist us in providing our application and services. We may also share your information with our affiliates or partners for marketing purposes. We will not sell or rent your information to third parties without your consent, except as required by law or as necessary to protect our rights and interests.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">Personally Identifiable Information you can access:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">We allow you to access the following information about you for the purpose of viewing, and in certain situations, updating that information. This list will change as World Tv Go product change. You may currently access the following information: user profile, and user preferences.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">What choices you have:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">When you register for the World Tv Go product, you have the option of checking a box to tell us that you do not want us to send you any information about our products and services, or that you do not want to receive information from our partners and others about products and services that might interest you. We will keep track of your decision in our database. Even if you choose not to receive information from us, we reserve the right to communicate with you on matters we consider especially important. Further, please note that if you do not want to receive legal notices from us, such as this Privacy Statement, those legal notices will still govern your use of the World Tv Go product, and you are responsible for reviewing such legal notices for changes. You are able to add or update certain information on pages, such as those listed in the Personally Identifiable Information you can access section above. When you update information, however, we often maintain a copy of the unrevised information in our records. You delete your account by calling the World Tv Go customer support line. Please note that some information may remain in our records after deletion of your account.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">Postings:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">If you use our bulletin boards, post user comments regarding content available through the World Tv Go, or engage in similar activity, please remember that anything you post is publicly available.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">Security:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">During sessions in which you give us information such as credit card numbers, our third-party payment system like stripe encrypts your transmissions using SSL (Secure Sockets Layer), and other security technology. This guards against the interception of the information while it is on the Internet. They keep the Personally Identifiable Information you provide on servers that are protected by firewalls and other technological means against intrusion or unauthorized access. They are located in a physically secure facility, however, there is no such thing as perfect security on the Internet. And any third party involvement such as Payment Solution, World Tv Go has no liability for the data such as the credit card number or bank account that you will disclose to the third party. We rely on you to select passwords that cannot be guessed easily and to safeguard those passwords from disclosure. Please contact us if you have any information regarding unauthorized use of&nbsp; World Tv Go.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">Data Deletion Request:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">You should contact us at </span><span id="docs-internal-guid-2d075019-7fff-8f6b-0286-06593c4d458f"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">hi@worldtvgo.com</span></span><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;"> and let us know why you want to delete your data with a screenshot of your user name which we created on our platform.&nbsp; After we verify your account, we will remove your data from our system in 7 days. If we fail to verify that the account is yours, your application will be canceled. We therefore recommend that you use your real name and other information so that we can easily verify your account and delete your data at your request.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">Prominent Disclosure &amp; Consent Requirement:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">At World Tv Go, we take your privacy very seriously and strive to ensure that all user data is protected. We believe transparency and informed consent are essential to maintaining your trust in our services. We have therefore made an important disclosure and consent requirement to ensure that you are fully aware of our data collection and processing practices and that you have given your express consent. with them.</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">By using our application, you consent to the collection, use and sharing of your personal data as described in this privacy policy. We collect information about you when you interact with our apps, including but not limited to your device information, location and usage data. This information is used to improve the functionality of the app, personalize your experience, and provide you with targeted advertising.</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">In order to provide certain services within the Application, we may need access to your device's camera, microphone and/or storage. This access will only be granted with your express consent and will be limited to the necessary functions of the application.</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">We may share your personal data with third party service providers with whom we work to provide you with the services of the application. These providers have a contractual obligation to maintain the confidentiality and security of your personal data and are only permitted to use it for the specific purposes for which we employ them. Please note that we may be required to disclose your personal data if we are required to do so by law or if we have a good faith belief that such disclosure is necessary to protect our rights or our interests or the rights or interests of others.</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">By using our application, you acknowledge that you have read and understood this privacy policy and that you consent to the collection, use and sharing of your personal data as described in This. If you do not agree with any part of this Privacy Policy, please do not use our App. If you have any questions or concerns regarding our data collection and processing practices, please contact us at</span><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;"> </span><span style="font-size: 10pt; font-family: Arial; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">hi@worldtvgo.com</span><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">Changes to this Privacy Statement:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">We may make changes to this Privacy Statement from time to time for any reason. Use of information we collect now is subject to the Privacy Statement in effect at the time such information is used (though you always have the option to delete your account as described above). If we make changes in the way we use Personally Identifiable Information, we will notify you via e-mail or by posting an announcement on our website.</span></p><br><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-weight: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">Contact Us</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">If you have any questions, concerns, or requests regarding this Privacy Policy or our information practices, please contact us at:</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">World Tv Go</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 10pt; font-family: Arial; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">hi@worldtvgo.com</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">KOPO YAMATO BLDG #2F, TATEISHI 5-24-8, KATSUSHIKA-KU, TOKYO 124-0012</span></p><p dir="ltr" style="line-height:1.38;margin-top:0pt;margin-bottom:0pt;"><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;">By using the App, you consent to the collection, use, and sharing of your personal information as described in this Privacy Policy.</span></p><div><span style="font-size: 12pt; font-family: &quot;Times New Roman&quot;; background-color: transparent; font-variant-numeric: normal; font-variant-east-asian: normal; font-variant-alternates: normal; vertical-align: baseline; white-space-collapse: preserve;"><br></span></div></span></h4> </section>`
        }
    });
});

app.get('/api/v1/policy/terms', (req, res) => {
    res.json({
        status: true,
        data: {
            terms: `section class="toc-body forall"> <h3 class="heading">Terms and Condition</h3> <h4> 1. Acceptance of Terms of Use.</h4> <p style="text-align:justify"> IT IS IMPORTANT THAT YOU READ ALL THE TERMS AND CONDITIONS CAREFULLY. BY USING AND/OR VISITING THIS WEBSITE (collectively, including all Content available through the www.worldtvgo.com domain name, the Android and iOS App"), YOU SIGNIFY YOUR ASSENT TO THESE TERMS AND CONDITIONS. If you do not agree to any of these terms, then please do not use the worldtvgo applications..</p> <h4>2. WorldTv Go Applications</h4> <p style="text-align:justify"> These Terms of Service apply to all users of the World TV GO Applications. The World TV GO Applications may contain links to third party channels. World TV Go assumes no responsibility for, the content, privacy policies, or practices of any third party websites. In addition, World TV GO will not and cannot censor or edit the content of any third-party site. By using the World TV Go Application, you expressly relieve World TV GO from any and all liability arising from your use of any third-party website.</p> <h4> 3. Website Access</h4> <p style="text-align:justify"> A. WorldTV GO hereby grants you permission to use the Website, provided that: (i) your use of the Website as permitted is solely for your personal, noncommercial use; (ii) you will not copy or distribute any part of the Website in any medium without WorldTV GO prior written authorization; (iii) you will not alter or modify any part of the Website other than as may be reasonably necessary to use the Website for its intended purpose; and (iv) you will otherwise comply with the terms and conditions of these Terms of Service.</p> <p style="text-align:justify"> B. You agree not to use or launch any automated system, including without limitation, "robots," "spiders," "offline readers," etc., that accesses the Website in a manner that sends more request messages to the WorldTV GO servers in a given period of time than a human can reasonably produce in the same period by using a convention on-line web browser. Notwithstanding the foregoing, WorldTV GO grants the operators of public search engines permission to use spiders to copy materials from the site for the sole purpose of creating publicly available searchable indices of the materials.</p> <h4> 4. Intellectual Property Rights</h4> <p style="text-align:justify"> The content on the WorldTV GO Website, except third party videostreams, including without limitation, the text, software, scripts, graphics, photos, sounds, interactive features and the like ("Content") and the trademarks, service marks and logos contained therein ("Marks"), are owned by WorldTV GO, subject to copyright and other intellectual property rights under Japanese and foreign laws and international conventions. Content on the Website is provided to you AS IS for your information and personal use only and may not be used, copied, reproduced, distributed, transmitted, broadcast, displayed, sold, licensed, or otherwise exploited for any other purposes whatsoever without the prior written consent of the respective owners. WorldTV GO reserves all rights not expressly granted in and to the Website and the Content. You agree to not engage in the use, copying, or distribution of any of the Content other than expressly permitted herein, including any use, copying, or distribution of User Submissions of third parties obtained through the Website for any commercial purposes. If you download or print a copy of the Content for personal use, you must retain all copyright and other proprietary notices contained therein. You agree not to circumvent, disable or otherwise interfere with security related features of the WorldTV GO Website or features that prevent or restrict use or copying of any Content or enforce limitations on use of the WorldTV GO Website or the Content therein.</p> <h4> 5. DISCLAIMER OF WARRANTIES.</h4> <p style="text-align:justify"> THE WEBSITE AND ALL CONTENT IS PROVIDED AS IS. BY ACCESSING AND USING THE WEBSITE YOU ACKNOWLEDGE AND AGREE THAT USE OF THE WEBSITE AND THE CONTENT IS ENTIRELY AT YOUR OWN RISK. WorldTV GO MAKES NO REPRESENTATIONS OR WARRANTIES REGARDING THE WEBSITE AND THE CONTENT, INCLUDING, WITHOUT LIMITATION, NO REPRESENTATION OR WARRANTY (I) THAT THE WEBSITE AND/OR CONTENT WILL BE ACCURATE, COMPLETE, RELIABLE, SUITABLE OR TIMELY; (II) THAT ANY CONTENT, INCLUDING, WITHOUT LIMITATION, ANY INFORMATION, DATA, SOFTWARE, PRODUCT OR SERVICE CONTAINED IN OR MADE AVAILABLE THROUGH THE WEBSITE WILL BE OF MERCHANTABLE QUALITY OR FIT FOR A PARTICULAR PURPOSE; III) THAT THE OPERATION OF THE WEBSITE WILL BE UNINTERRUPTED OR ERROR FREE; (IV) THAT DEFECTS OR ERRORS IN THE WEBSITE WILL BE CORRECTED; (V) THAT THE WEBSITE WILL BE FREE FROM VIRUSES OR HARMFUL COMPONENTS; AND (VI) THAT COMMUNICATIONS TO OR FROM THE WEBSITE WILL BE SECURE OR NOT INTERCEPTED.</p> <h4> 6. LIMITATION OF LIABILITY.</h4> <p style="text-align:justify"> SUBJECT TO APPLICABLE LAW, IN NO EVENT SHALL WorldTV GO, ITS OFFICERS, DIRECTORS, EMPLOYEES, OR AGENTS, LICENSORS OR THEIR RESPECTIVE SUCCESSORS AND ASSIGNS, BE LIABLE TO YOU FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, PUNITIVE, OR CONSEQUENTIAL DAMAGES WHATSOEVER RESULTING FROM ANY (I) ERRORS, MISTAKES, OR INACCURACIES OF CONTENT, (II) PERSONAL INJURY OR PROPERTY DAMAGE, OF ANY NATURE WHATSOEVER, RESULTING FROM YOUR ACCESS TO AND USE OF OUR WEBSITE, (III) ANY INTERRUPTION OR CESSATION OF TRANSMISSION TO OR FROM OUR WEBSITE, (IV) ANY BUGS, VIRUSES, TROJAN HORSES, OR THE LIKE, WHICH MAY BE TRANSMITTED TO OR THROUGH OUR WEBSITE BY ANY THIRD PARTY, AND/OR (V) ANY ERRORS OR OMISSIONS IN ANY CONTENT OR FOR ANY LOSS OR DAMAGE OF ANY KIND INCURRED AS A RESULT OF YOUR USE OF ANY CONTENT POSTED, EMAILED, TRANSMITTED, OR OTHERWISE MADE AVAILABLE VIA THE WorldTV GO WEBSITE, WHETHER BASED ON WARRANTY, CONTRACT, TORT, OR ANY OTHER LEGAL THEORY, AND WHETHER OR NOT THE COMPANY IS ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. THE FOREGOING LIMITATION OF LIABILITY SHALL APPLY TO THE FULLEST EXTENT PERMITTED BY LAW IN THE APPLICABLE JURISDICTION. IF YOU DECIDE TO ACCESS OR USE ANY LINKED WEB SITE OR CONTENT, MATERIALS, SOFTWARE, GOODS OR SERVICES FROM A WEB SITE LINKED TO THE WEBSITE, YOU DO SO ENTIRELY AT YOUR OWN RISK.</p> <h4> 7. Indemnity</h4> <p style="text-align:justify"> You agree to defend, indemnify and hold harmless WorldTV GO, its parent corporation, officers, directors, employees and agents, from and against any and all claims, damages, obligations, losses, liabilities, costs or debt, and expenses (including but not limited to attorney's fees) arising from: (i) your use of and access to the WorldTV GO Website; (ii) your violation of any term of these Terms of Service; (iii) your violation of any third party right, including without limitation any copyright, property, or privacy right; or (iv) any claim that one of your User Submissions caused damage to a third party. This defense and indemnification obligation will survive these Terms of Service and your use of the WorldTV GO Website.</p> <h4> 8. Assignment</h4> <p style="text-align:justify"> These Terms of Use, and any rights and licenses granted hereunder, may not be transferred or assigned by you, but may be assigned by WorldTV GO without restriction.</p> <h4> 9. Linking.</h4> <p style="text-align:justify"> The Web site contains links to third-party web sites. These links appears for information purposes only and are provided solely as a convenience to you and not as an endorsement by WorldTV GO of the contents of such third-party web sites. WorldTV GO is not responsible for the content of any third-party web site, nor does it make any representation or warranty of any kind regarding any third-party web site including, without limitation (i) any representation or warranty regarding the legality, accuracy, reliability, completeness, timeliness, suitability of any content on any third-party web site; (ii) any representation or warranty regarding the merchantability or fitness for a particular purpose of any material, content, software, goods or services located at or made available through such third-party web sites; or (iii) any representation or warranty that the operation of the third-party web sites will be uninterrupted or error free, that defects or errors in such third-party websites will be corrected or that such third-party websites will be free from viruses or other harmful components. While WorldTV GO encourages links to the Web site, it does not wish to be linked to or from any third-party web site which (i) contains, posts or transmits any unlawful, threatening, abusive, libellous, defamatory, obscene, vulgar, pornographic, profane or indecent information of any kind, including, without limitation, any content constituting or encouraging conduct that would constitute a criminal offense, give rise to civil liability or otherwise violate any local, state, provincial, national or international law, regulation which may be damaging or detrimental to the activities, operations, credibility or integrity of WorldTV GO or which contains, posts or transmits any material or information of any kind which promotes racism, bigotry, hatred or physical harm of any kind against any group or individual, could be harmful to minors, harasses or advocates harassment of another person, provides material that exploits people under the age of 18 in a sexual or violent manner, provides instructional information about illegal activities, including, without limitation, the making or buying of illegal weapons; or (ii) contains, posts or transmits any information, software or other material which violates or infringes upon the rights of others, including material which is an invasion of privacy or publicity rights, or which is protected by copyright, trademark or other proprietary rights. WorldTV GO reserves the right to prohibit or refuse to accept any link to the Web site, including, without limitation, any link which contains or makes available any content or information of the foregoing nature, at any time.</p> <h4> 10. General. </h4> <p style="text-align:justify"> You agree that : (i) the WorldTV GO Website shall be deemed solely based in Japan; and (ii) These Terms of Service shall be governed by the laws of the Japan, without respect to its conflict of laws principles. Any claim or dispute between you and WorldTV GO that arises in whole or in part from the WorldTV GO Website shall be decided exclusively by a court of competent jurisdiction located in Tokyo Japan. These Terms of Use and any other legal notices published by WorldTV GO on the Website, shall constitute the entire agreement between you and WorldTV GO concerning the WorldTV GO Website. If any provision of these Terms of Use is deemed invalid by a court of competent jurisdiction, the invalidity of such provision shall not affect the validity of the remaining provisions of these Terms of Service, which shall remain in full force and effect. No waiver of any term of these Terms of Service shall be deemed a further or continuing waiver of such term or any other term, and WorldTV GO 's failure to assert any right or provision under these Terms of Use shall not constitute a waiver of such right or provision. WorldTV GOreserves the right to amend these Terms of Use at any time and without notice, and it is your responsibility to review these Terms of Use for any changes. Your use of the WorldTV GO Website following any amendment of these Terms of Use will signify your assent to and acceptance of its revised terms. YOU AND WorldTV GO AGREE THAT ANY CAUSE OF ACTION ARISING OUT OF OR RELATED TO THE WorldTV GO WEBSITE MUST COMMENCE WITHIN ONE (1) YEAR AFTER THE CAUSE OF ACTION ACCRUES. OTHERWISE, SUCH CAUSE OF ACTION IS PERMANENTLY BARRED.</p> </section>`
        }
    })
})



// Start server
app.listen(port, async () => {
    await createUserTable();
    console.log(`🚀 API server running: http://localhost:${port}`);
});

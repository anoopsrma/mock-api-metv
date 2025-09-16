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
            { expiresIn: '2h' }
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

app.get('/api/v1/config', (req, res) => {
    res.json({
        status: true,
        data: {
            terms_and_conditions: "/api/v1/terms-and-conditions",
            privacy_policy: "/api/v1/privacy-policy",
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
            register: {
                "route": "api/v1/register",
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
            }
        }
    });
});

// Home
app.get('/api/v1/home', (req, res) => {
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
                            "start": "2025-09-12T00:00:00Z",
                            "end": "2025-09-12T01:00:00Z",
                            "genres": [
                                "Nature",
                                "Documentary"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_001",
                            "title": "Secrets of the Zoo",
                            "description": "Go behind the scenes at one of the largest zoos in the world.",
                            "start": "2025-09-12T01:00:00Z",
                            "end": "2025-09-12T02:00:00Z",
                            "genres": [
                                "Animal",
                                "Reality"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_002",
                            "title": "Engineering Marvels",
                            "description": "Discover how modern marvels are constructed from start to finish.",
                            "start": "2025-09-12T02:00:00Z",
                            "end": "2025-09-12T03:00:00Z",
                            "genres": [
                                "Science",
                                "Engineering"
                            ],
                            "rating": "7.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_003",
                            "title": "Wildlife SOS",
                            "description": "Follow rescue teams helping injured or endangered wild animals.",
                            "start": "2025-09-12T03:00:00Z",
                            "end": "2025-09-12T04:00:00Z",
                            "genres": [
                                "Wildlife",
                                "Rescue"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_004",
                            "title": "Mega Factories",
                            "description": "A look inside the world's most advanced production facilities.",
                            "start": "2025-09-12T04:00:00Z",
                            "end": "2025-09-12T05:00:00Z",
                            "genres": [
                                "Technology",
                                "Industry"
                            ],
                            "rating": "7.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_005",
                            "title": "Air Crash Investigation",
                            "description": "Explore the causes of major aviation disasters.",
                            "start": "2025-09-12T05:00:00Z",
                            "end": "2025-09-12T06:00:00Z",
                            "genres": [
                                "Investigation",
                                "Documentary"
                            ],
                            "rating": "PG-13",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_006",
                            "title": "Locked Up Abroad",
                            "description": "Real stories of people caught smuggling drugs or breaking laws overseas.",
                            "start": "2025-09-12T06:00:00Z",
                            "end": "2025-09-12T07:00:00Z",
                            "genres": [
                                "Crime",
                                "Drama"
                            ],
                            "rating": "TV-14",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_007",
                            "title": "Explorer",
                            "description": "Adventures from the frontiers of science and discovery.",
                            "start": "2025-09-12T07:00:00Z",
                            "end": "2025-09-12T08:00:00Z",
                            "genres": [
                                "Adventure",
                                "Science"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_008",
                            "title": "Brain Games",
                            "description": "Mind-bending challenges that explore the brain’s inner workings.",
                            "start": "2025-09-12T08:00:00Z",
                            "end": "2025-09-12T09:00:00Z",
                            "genres": [
                                "Science",
                                "Education"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_009",
                            "title": "Cosmos: A Spacetime Odyssey",
                            "description": "A journey through the universe and the laws of nature.",
                            "start": "2025-09-12T09:00:00Z",
                            "end": "2025-09-12T10:00:00Z",
                            "genres": [
                                "Science",
                                "Space"
                            ],
                            "rating": "7.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_010",
                            "title": "Running Wild",
                            "description": "Survival experts take celebrities into the wild.",
                            "start": "2025-09-12T10:00:00Z",
                            "end": "2025-09-12T11:00:00Z",
                            "genres": [
                                "Adventure",
                                "Reality"
                            ],
                            "rating": "7.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_011",
                            "title": "Animal Fight Club",
                            "description": "Nature’s most aggressive battles between animals.",
                            "start": "2025-09-12T11:00:00Z",
                            "end": "2025-09-12T12:00:00Z",
                            "genres": [
                                "Wildlife",
                                "Action"
                            ],
                            "rating": "TV-14",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_012",
                            "title": "Drain the Oceans",
                            "description": "3D scanning reveals secrets hidden beneath the oceans.",
                            "start": "2025-09-12T12:00:00Z",
                            "end": "2025-09-12T13:00:00Z",
                            "genres": [
                                "Science",
                                "Marine"
                            ],
                            "rating": "7.5",
                            "is_live": true,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_013",
                            "title": "Lost Cities",
                            "description": "Explore ancient ruins and civilizations with modern technology.",
                            "start": "2025-09-12T13:00:00Z",
                            "end": "2025-09-12T14:00:00Z",
                            "genres": [
                                "History",
                                "Archaeology"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_014",
                            "title": "Mars: Inside SpaceX",
                            "description": "Inside Elon Musk's plan to colonize Mars.",
                            "start": "2025-09-12T14:00:00Z",
                            "end": "2025-09-12T15:00:00Z",
                            "genres": [
                                "Science",
                                "Technology"
                            ],
                            "rating": "7.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_015",
                            "title": "Ultimate Airport Dubai",
                            "description": "Behind the scenes of one of the world's busiest airports.",
                            "start": "2025-09-12T15:00:00Z",
                            "end": "2025-09-12T16:00:00Z",
                            "genres": [
                                "Reality",
                                "Travel"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_016",
                            "title": "Nazi Megastructures",
                            "description": "Exploring Hitler’s massive military infrastructure.",
                            "start": "2025-09-12T16:00:00Z",
                            "end": "2025-09-12T17:00:00Z",
                            "genres": [
                                "History",
                                "War"
                            ],
                            "rating": "PG-13",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_017",
                            "title": "The Hot Zone",
                            "description": "Docudrama about deadly virus outbreaks.",
                            "start": "2025-09-12T17:00:00Z",
                            "end": "2025-09-12T18:00:00Z",
                            "genres": [
                                "Drama",
                                "Science"
                            ],
                            "rating": "TV-14",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_018",
                            "title": "Mars",
                            "description": "A blend of drama and documentary about the future of Mars exploration.",
                            "start": "2025-09-12T18:00:00Z",
                            "end": "2025-09-12T19:00:00Z",
                            "genres": [
                                "Science Fiction",
                                "Space"
                            ],
                            "rating": "TV-PG",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_019",
                            "title": "The Story of God with Morgan Freeman",
                            "description": "Exploring different cultures’ views on God and spirituality.",
                            "start": "2025-09-12T19:00:00Z",
                            "end": "2025-09-12T20:00:00Z",
                            "genres": [
                                "Religion",
                                "Documentary"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_020",
                            "title": "Science of Stupid",
                            "description": "Funny fails with a scientific explanation.",
                            "start": "2025-09-12T20:00:00Z",
                            "end": "2025-09-12T21:00:00Z",
                            "genres": [
                                "Comedy",
                                "Science"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_021",
                            "title": "Great Migrations",
                            "description": "Witness the planet’s greatest animal migrations.",
                            "start": "2025-09-12T21:00:00Z",
                            "end": "2025-09-12T22:00:00Z",
                            "genres": [
                                "Nature",
                                "Wildlife"
                            ],
                            "rating": "8.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_022",
                            "title": "Explorer: Deep Sea",
                            "description": "Uncovering the mysteries of the deep ocean.",
                            "start": "2025-09-12T22:00:00Z",
                            "end": "2025-09-12T23:00:00Z",
                            "genres": [
                                "Marine",
                                "Science"
                            ],
                            "rating": "7.5",
                            "is_live": false,
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_023",
                            "title": "The Next Megaquake",
                            "description": "The science and predictions of future large earthquakes.",
                            "start": "2025-09-12T23:00:00Z",
                            "end": "2025-09-13T00:00:00Z",
                            "genres": [
                                "Science",
                                "Disaster"
                            ],
                            "is_live": false,
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
                            "route": "api/v1/movies/d9428888-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428889-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428890-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428892-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428893-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428894-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428895-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428896-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428897-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428898-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d9428899-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d94288a0-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d94288a1-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d94288a2-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d94288a3-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d94288a4-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d94288a5-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d94288a6-122b-11e1-b85c-61cd3cbb3210",
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
                            "route": "api/v1/movies/d94288a7-122b-11e1-b85c-61cd3cbb3210",
                            "genres": [
                                "Drama",
                                "Mystery"
                            ],
                            "epg": ""
                        }
                    ]
                },
                {
                    "name": "Genres",
                    "route": "/api/v1/genres",
                    "list": [
                        {
                            "id": "d94288a8-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Action",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.5",
                            "release_year": 2006,
                            "is_live": false,
                            "route": "api/v1/genres/d94288a8-122b-11e1-b85c-61cd3cbb3210",
                            "genres": [],
                            "epg": ""
                        },
                        {
                            "id": "d94288a9-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Comedy",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.5",
                            "release_year": 2006,
                            "is_live": false,
                            "route": "api/v1/genres/d94288a9-122b-11e1-b85c-61cd3cbb3210",
                            "genres": [],
                            "epg": ""
                        },
                        {
                            "id": "d94288aa-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Drama",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.5",
                            "release_year": 2006,
                            "is_live": false,
                            "route": "api/v1/genres/d94288aa-122b-11e1-b85c-61cd3cbb3210",
                            "genres": [],
                            "epg": ""
                        },
                        {
                            "id": "d94288ab-122b-11e1-b85c-61cd3cbb3210",
                            "title": "Horror",
                            "poster": "https://picsum.photos/600/400",
                            "rating": "8.5",
                            "release_year": 2006,
                            "is_live": false,
                            "route": "api/v1/genres/d94288ab-122b-11e1-b85c-61cd3cbb3210",
                            "genres": [],
                            "epg": ""
                        }
                    ]
                }
            ]
        }
    }
    )
})

// Stream
app.get('/api/v1/movies/:channelId/stream', (req, res) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            status: false,
            message: 'Unauthorized: Bearer token missing or malformed'
        });
    }

    res.json({
        status: true,
        data: {
            "is_dvr": true,
            "price": 5.00,
            "genre": [
                "Action",
                "Comedy"
            ],
            "description": "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.",
            "url": "https://ntvedge.truestreamz.com/ntvlive/ntvithari-abr.stream/playlist_dvr.m3u8",
            "next_program": [
                {
                    "id": "d9428888-122b-11e1-b85c-61cd3cbb3210",
                    "title": "The Flash",
                    "poster": "https://picsum.photos/600/400",
                    "rating": "8.2",
                    "release_year": 2023,
                    "is_live": false,
                    "route": "api/v1/movies/d9428888-122b-11e1-b85c-61cd3cbb3210",
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
                    "route": "api/v1/movies/d9428889-122b-11e1-b85c-61cd3cbb3210",
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
                    "route": "api/v1/movies/d9428890-122b-11e1-b85c-61cd3cbb3210",
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
                    "route": "api/v1/movies/d9428892-122b-11e1-b85c-61cd3cbb3210",
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

app.get('/api/v1/epgs/:channelId', async (req, res) => {
    const channelId = req.params.channelId;
    res.json({
        status: true,
        data: {
            epgs: [
                {
                    "date": "12-09-2025",
                    "channel": {
                        "id": "channel_101",
                        "name": "National Geographic",
                        "number": "101",
                        "logo": "https://picsum.photos/600/400"
                    },
                    "epg": [
                        {
                            "id": "epg_000",
                            "title": "Planet Earth: Ice Worlds",
                            "description": "Explore the icy habitats of polar regions and the species that survive there.",
                            "start": "2025-09-12T00:00:00Z",
                            "end": "2025-09-12T01:00:00Z",
                            "genres": [
                                "Nature",
                                "Documentary"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_001",
                            "title": "Secrets of the Zoo",
                            "description": "Go behind the scenes at one of the largest zoos in the world.",
                            "start": "2025-09-12T01:00:00Z",
                            "end": "2025-09-12T02:00:00Z",
                            "genres": [
                                "Animal",
                                "Reality"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_002",
                            "title": "Engineering Marvels",
                            "description": "Discover how modern marvels are constructed from start to finish.",
                            "start": "2025-09-12T02:00:00Z",
                            "end": "2025-09-12T03:00:00Z",
                            "genres": [
                                "Science",
                                "Engineering"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_003",
                            "title": "Wildlife SOS",
                            "description": "Follow rescue teams helping injured or endangered wild animals.",
                            "start": "2025-09-12T03:00:00Z",
                            "end": "2025-09-12T04:00:00Z",
                            "genres": [
                                "Wildlife",
                                "Rescue"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_004",
                            "title": "Mega Factories",
                            "description": "A look inside the world's most advanced production facilities.",
                            "start": "2025-09-12T04:00:00Z",
                            "end": "2025-09-12T05:00:00Z",
                            "genres": [
                                "Technology",
                                "Industry"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_005",
                            "title": "Air Crash Investigation",
                            "description": "Explore the causes of major aviation disasters.",
                            "start": "2025-09-12T05:00:00Z",
                            "end": "2025-09-12T06:00:00Z",
                            "genres": [
                                "Investigation",
                                "Documentary"
                            ],
                            "rating": "PG-13",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_006",
                            "title": "Locked Up Abroad",
                            "description": "Real stories of people caught smuggling drugs or breaking laws overseas.",
                            "start": "2025-09-12T06:00:00Z",
                            "end": "2025-09-12T07:00:00Z",
                            "genres": [
                                "Crime",
                                "Drama"
                            ],
                            "rating": "TV-14",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_007",
                            "title": "Explorer",
                            "description": "Adventures from the frontiers of science and discovery.",
                            "start": "2025-09-12T07:00:00Z",
                            "end": "2025-09-12T08:00:00Z",
                            "genres": [
                                "Adventure",
                                "Science"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_008",
                            "title": "Brain Games",
                            "description": "Mind-bending challenges that explore the brain’s inner workings.",
                            "start": "2025-09-12T08:00:00Z",
                            "end": "2025-09-12T09:00:00Z",
                            "genres": [
                                "Science",
                                "Education"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_009",
                            "title": "Cosmos: A Spacetime Odyssey",
                            "description": "A journey through the universe and the laws of nature.",
                            "start": "2025-09-12T09:00:00Z",
                            "end": "2025-09-12T10:00:00Z",
                            "genres": [
                                "Science",
                                "Space"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_010",
                            "title": "Running Wild",
                            "description": "Survival experts take celebrities into the wild.",
                            "start": "2025-09-12T10:00:00Z",
                            "end": "2025-09-12T11:00:00Z",
                            "genres": [
                                "Adventure",
                                "Reality"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_011",
                            "title": "Animal Fight Club",
                            "description": "Nature’s most aggressive battles between animals.",
                            "start": "2025-09-12T11:00:00Z",
                            "end": "2025-09-12T12:00:00Z",
                            "genres": [
                                "Wildlife",
                                "Action"
                            ],
                            "rating": "TV-14",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_012",
                            "title": "Drain the Oceans",
                            "description": "3D scanning reveals secrets hidden beneath the oceans.",
                            "start": "2025-09-12T12:00:00Z",
                            "end": "2025-09-12T13:00:00Z",
                            "genres": [
                                "Science",
                                "Marine"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_013",
                            "title": "Lost Cities",
                            "description": "Explore ancient ruins and civilizations with modern technology.",
                            "start": "2025-09-12T13:00:00Z",
                            "end": "2025-09-12T14:00:00Z",
                            "genres": [
                                "History",
                                "Archaeology"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_014",
                            "title": "Mars: Inside SpaceX",
                            "description": "Inside Elon Musk's plan to colonize Mars.",
                            "start": "2025-09-12T14:00:00Z",
                            "end": "2025-09-12T15:00:00Z",
                            "genres": [
                                "Science",
                                "Technology"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_015",
                            "title": "Ultimate Airport Dubai",
                            "description": "Behind the scenes of one of the world's busiest airports.",
                            "start": "2025-09-12T15:00:00Z",
                            "end": "2025-09-12T16:00:00Z",
                            "genres": [
                                "Reality",
                                "Travel"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_016",
                            "title": "Nazi Megastructures",
                            "description": "Exploring Hitler’s massive military infrastructure.",
                            "start": "2025-09-12T16:00:00Z",
                            "end": "2025-09-12T17:00:00Z",
                            "genres": [
                                "History",
                                "War"
                            ],
                            "rating": "PG-13",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_017",
                            "title": "The Hot Zone",
                            "description": "Docudrama about deadly virus outbreaks.",
                            "start": "2025-09-12T17:00:00Z",
                            "end": "2025-09-12T18:00:00Z",
                            "genres": [
                                "Drama",
                                "Science"
                            ],
                            "rating": "TV-14",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_018",
                            "title": "Mars",
                            "description": "A blend of drama and documentary about the future of Mars exploration.",
                            "start": "2025-09-12T18:00:00Z",
                            "end": "2025-09-12T19:00:00Z",
                            "genres": [
                                "Science Fiction",
                                "Space"
                            ],
                            "rating": "TV-PG",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_019",
                            "title": "The Story of God with Morgan Freeman",
                            "description": "Exploring different cultures’ views on God and spirituality.",
                            "start": "2025-09-12T19:00:00Z",
                            "end": "2025-09-12T20:00:00Z",
                            "genres": [
                                "Religion",
                                "Documentary"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_020",
                            "title": "Science of Stupid",
                            "description": "Funny fails with a scientific explanation.",
                            "start": "2025-09-12T20:00:00Z",
                            "end": "2025-09-12T21:00:00Z",
                            "genres": [
                                "Comedy",
                                "Science"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_021",
                            "title": "Great Migrations",
                            "description": "Witness the planet’s greatest animal migrations.",
                            "start": "2025-09-12T21:00:00Z",
                            "end": "2025-09-12T22:00:00Z",
                            "genres": [
                                "Nature",
                                "Wildlife"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_022",
                            "title": "Explorer: Deep Sea",
                            "description": "Uncovering the mysteries of the deep ocean.",
                            "start": "2025-09-12T22:00:00Z",
                            "end": "2025-09-12T23:00:00Z",
                            "genres": [
                                "Marine",
                                "Science"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_023",
                            "title": "The Next Megaquake",
                            "description": "The science and predictions of future large earthquakes.",
                            "start": "2025-09-12T23:00:00Z",
                            "end": "2025-09-13T00:00:00Z",
                            "genres": [
                                "Science",
                                "Disaster"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        }
                    ]
                },
                {
                    "date": "13-09-2025",
                    "channel": {
                        "id": "channel_101",
                        "name": "National Geographic",
                        "number": "101",
                        "logo": "https://picsum.photos/600/400"
                    },
                    "epg": [
                        {
                            "id": "epg_000",
                            "title": "Planet Earth: Ice Worlds",
                            "description": "Explore the icy habitats of polar regions and the species that survive there.",
                            "start": "2025-09-12T00:00:00Z",
                            "end": "2025-09-12T01:00:00Z",
                            "genres": [
                                "Nature",
                                "Documentary"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_001",
                            "title": "Secrets of the Zoo",
                            "description": "Go behind the scenes at one of the largest zoos in the world.",
                            "start": "2025-09-12T01:00:00Z",
                            "end": "2025-09-12T02:00:00Z",
                            "genres": [
                                "Animal",
                                "Reality"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_002",
                            "title": "Engineering Marvels",
                            "description": "Discover how modern marvels are constructed from start to finish.",
                            "start": "2025-09-12T02:00:00Z",
                            "end": "2025-09-12T03:00:00Z",
                            "genres": [
                                "Science",
                                "Engineering"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_003",
                            "title": "Wildlife SOS",
                            "description": "Follow rescue teams helping injured or endangered wild animals.",
                            "start": "2025-09-12T03:00:00Z",
                            "end": "2025-09-12T04:00:00Z",
                            "genres": [
                                "Wildlife",
                                "Rescue"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_004",
                            "title": "Mega Factories",
                            "description": "A look inside the world's most advanced production facilities.",
                            "start": "2025-09-12T04:00:00Z",
                            "end": "2025-09-12T05:00:00Z",
                            "genres": [
                                "Technology",
                                "Industry"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_005",
                            "title": "Air Crash Investigation",
                            "description": "Explore the causes of major aviation disasters.",
                            "start": "2025-09-12T05:00:00Z",
                            "end": "2025-09-12T06:00:00Z",
                            "genres": [
                                "Investigation",
                                "Documentary"
                            ],
                            "rating": "PG-13",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_006",
                            "title": "Locked Up Abroad",
                            "description": "Real stories of people caught smuggling drugs or breaking laws overseas.",
                            "start": "2025-09-12T06:00:00Z",
                            "end": "2025-09-12T07:00:00Z",
                            "genres": [
                                "Crime",
                                "Drama"
                            ],
                            "rating": "TV-14",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_007",
                            "title": "Explorer",
                            "description": "Adventures from the frontiers of science and discovery.",
                            "start": "2025-09-12T07:00:00Z",
                            "end": "2025-09-12T08:00:00Z",
                            "genres": [
                                "Adventure",
                                "Science"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_008",
                            "title": "Brain Games",
                            "description": "Mind-bending challenges that explore the brain’s inner workings.",
                            "start": "2025-09-12T08:00:00Z",
                            "end": "2025-09-12T09:00:00Z",
                            "genres": [
                                "Science",
                                "Education"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_009",
                            "title": "Cosmos: A Spacetime Odyssey",
                            "description": "A journey through the universe and the laws of nature.",
                            "start": "2025-09-12T09:00:00Z",
                            "end": "2025-09-12T10:00:00Z",
                            "genres": [
                                "Science",
                                "Space"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_010",
                            "title": "Running Wild",
                            "description": "Survival experts take celebrities into the wild.",
                            "start": "2025-09-12T10:00:00Z",
                            "end": "2025-09-12T11:00:00Z",
                            "genres": [
                                "Adventure",
                                "Reality"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_011",
                            "title": "Animal Fight Club",
                            "description": "Nature’s most aggressive battles between animals.",
                            "start": "2025-09-12T11:00:00Z",
                            "end": "2025-09-12T12:00:00Z",
                            "genres": [
                                "Wildlife",
                                "Action"
                            ],
                            "rating": "TV-14",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_012",
                            "title": "Drain the Oceans",
                            "description": "3D scanning reveals secrets hidden beneath the oceans.",
                            "start": "2025-09-12T12:00:00Z",
                            "end": "2025-09-12T13:00:00Z",
                            "genres": [
                                "Science",
                                "Marine"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_013",
                            "title": "Lost Cities",
                            "description": "Explore ancient ruins and civilizations with modern technology.",
                            "start": "2025-09-12T13:00:00Z",
                            "end": "2025-09-12T14:00:00Z",
                            "genres": [
                                "History",
                                "Archaeology"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_014",
                            "title": "Mars: Inside SpaceX",
                            "description": "Inside Elon Musk's plan to colonize Mars.",
                            "start": "2025-09-12T14:00:00Z",
                            "end": "2025-09-12T15:00:00Z",
                            "genres": [
                                "Science",
                                "Technology"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_015",
                            "title": "Ultimate Airport Dubai",
                            "description": "Behind the scenes of one of the world's busiest airports.",
                            "start": "2025-09-12T15:00:00Z",
                            "end": "2025-09-12T16:00:00Z",
                            "genres": [
                                "Reality",
                                "Travel"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_016",
                            "title": "Nazi Megastructures",
                            "description": "Exploring Hitler’s massive military infrastructure.",
                            "start": "2025-09-12T16:00:00Z",
                            "end": "2025-09-12T17:00:00Z",
                            "genres": [
                                "History",
                                "War"
                            ],
                            "rating": "PG-13",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_017",
                            "title": "The Hot Zone",
                            "description": "Docudrama about deadly virus outbreaks.",
                            "start": "2025-09-12T17:00:00Z",
                            "end": "2025-09-12T18:00:00Z",
                            "genres": [
                                "Drama",
                                "Science"
                            ],
                            "rating": "TV-14",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_018",
                            "title": "Mars",
                            "description": "A blend of drama and documentary about the future of Mars exploration.",
                            "start": "2025-09-12T18:00:00Z",
                            "end": "2025-09-12T19:00:00Z",
                            "genres": [
                                "Science Fiction",
                                "Space"
                            ],
                            "rating": "TV-PG",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_019",
                            "title": "The Story of God with Morgan Freeman",
                            "description": "Exploring different cultures’ views on God and spirituality.",
                            "start": "2025-09-12T19:00:00Z",
                            "end": "2025-09-12T20:00:00Z",
                            "genres": [
                                "Religion",
                                "Documentary"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_020",
                            "title": "Science of Stupid",
                            "description": "Funny fails with a scientific explanation.",
                            "start": "2025-09-12T20:00:00Z",
                            "end": "2025-09-12T21:00:00Z",
                            "genres": [
                                "Comedy",
                                "Science"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_021",
                            "title": "Great Migrations",
                            "description": "Witness the planet’s greatest animal migrations.",
                            "start": "2025-09-12T21:00:00Z",
                            "end": "2025-09-12T22:00:00Z",
                            "genres": [
                                "Nature",
                                "Wildlife"
                            ],
                            "rating": "8.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_022",
                            "title": "Explorer: Deep Sea",
                            "description": "Uncovering the mysteries of the deep ocean.",
                            "start": "2025-09-12T22:00:00Z",
                            "end": "2025-09-12T23:00:00Z",
                            "genres": [
                                "Marine",
                                "Science"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        },
                        {
                            "id": "epg_023",
                            "title": "The Next Megaquake",
                            "description": "The science and predictions of future large earthquakes.",
                            "start": "2025-09-12T23:00:00Z",
                            "end": "2025-09-13T00:00:00Z",
                            "genres": [
                                "Science",
                                "Disaster"
                            ],
                            "rating": "7.5",
                            "thumbnail": "https://picsum.photos/600/400"
                        }
                    ]
                }
            ]
        }
    });
})

app.get('/api/v1/version/check', (req, res) => {
    const clientVersion = req.query.version || '0.0.0';
    const is_maintanence = req.query.is_maintanence || false;
    const latestVersion = '1.0.1';
    const forceUpdateVersion = '1.0.0';
    const update = isVersionLessThan(clientVersion, latestVersion);
    const forceUpdate = isVersionLessThan(clientVersion, forceUpdateVersion);
    res.json({
        status: true,
        data: {
            update: update,
            update_type: forceUpdate ? 'force' : 'normal',
            is_maintanence: is_maintanence,
            message: "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries"
        }
    });
});

// Simple version comparison function
function isVersionLessThan(v1, v2) {
    const v1Parts = v1.split('.').map(Number);
    const v2Parts = v2.split('.').map(Number);

    for (let i = 0; i < 3; i++) {
        if ((v1Parts[i] || 0) < (v2Parts[i] || 0)) return true;
        if ((v1Parts[i] || 0) > (v2Parts[i] || 0)) return false;
    }
    return false; // versions are equal
}
  
  

// Start server
app.listen(port, async () => {
    await createUserTable();
    console.log(`🚀 API server running: http://localhost:${port}`);
});

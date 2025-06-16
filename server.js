// --- NEW: Require and configure dotenv ---
// This should be at the very top of your file
require('dotenv').config();

const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// --- FIX: Read credentials from environment variables ---
// Provide sensible defaults in case they aren't set
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password123';

const saltRounds = 10;

// --- Data management ---
let users = {};
let experts = {};
let referrals = {};
let bookings = {};
let founders = {};
let affiliatePrograms = []; // To hold loaded programs
let affiliateClicks = [];   // To hold recorded clicks (in-memory for now)


// --- Middleware Setup ---
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-default-secret-key', // Also use an env var for the session secret!
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 20 * 60 * 1000 }
}));

const requireLogin = (req, res, next) => {
    // Check if a user is logged in via session
    if (!req.session.userId) {
        // For API-like requests, send a JSON error. For page navigation, redirect.
        if (req.headers.accept && req.headers.accept.includes('json')) {
            return res.status(401).json({ error: 'Unauthorized, please log in' });
        }
        return res.redirect('/auth.html');
    }

    // Check if the user is blocked
    const user = users[req.session.userId];
    if (user && user.blocked) {
        req.session.destroy(); // Log out blocked users
        return res.status(403).json({ error: 'This account has been blocked.' });
    }
    next();
};

const authMiddleware = (req, res, next) => {
    // Check for admin status in session
    if (req.session.isAdmin) {
       return next();
    }
    
    // Check for Basic Auth headers as a fallback
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [username, password] = credentials.split(':');
        if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            req.session.userId = username;
            req.session.isAdmin = true;
            return next();
        }
    }

    // If neither session nor Basic Auth is valid, deny access
    if (req.headers.accept && req.headers.accept.includes('json')) {
        return res.status(403).json({ error: 'Forbidden: Admin access required.' });
    }
    return res.status(403).send('<h1>403 Forbidden</h1><p>You do not have permission to view this page.</p>');
};

// --- Data Loading Functions ---

async function loadUsers() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'users.json'), 'utf8');
        users = JSON.parse(data);
        console.log('Users loaded');
    } catch (err) {
        if (err.code === 'ENOENT') {
             console.log('users.json not found, creating a new file.');
             users = {};
        } else {
            console.error('Error loading users:', err);
            users = {};
        }
        await fs.writeFile(path.join(__dirname, 'users.json'), JSON.stringify(users, null, 2));
    }
}

async function saveUsers() {
    try {
        await fs.writeFile(path.join(__dirname, 'users.json'), JSON.stringify(users, null, 2));
        console.log('Users saved');
    } catch (err) {
        console.error('Error saving users:', err);
    }
}

async function loadExperts() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'experts.json'), 'utf8');
        experts = JSON.parse(data);
        console.log('Experts loaded');
    } catch (err) {
        experts = {};
        console.error('Error loading experts.json:', err.code);
        await fs.writeFile(path.join(__dirname, 'experts.json'), JSON.stringify(experts, null, 2));
    }
}

async function saveExperts() {
    try {
        await fs.writeFile(path.join(__dirname, 'experts.json'), JSON.stringify(experts, null, 2));
        console.log('Experts saved');
    } catch (err) {
        console.error('Error saving experts:', err);
    }
}

async function loadReferrals() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'referrals.json'), 'utf8');
        referrals = JSON.parse(data);
        console.log('Referrals loaded');
    } catch (err) {
        referrals = {};
        console.error('Error loading referrals.json:', err.code);
        await fs.writeFile(path.join(__dirname, 'referrals.json'), JSON.stringify({}, null, 2));
    }
}

async function saveReferrals() {
    try {
        await fs.writeFile(path.join(__dirname, 'referrals.json'), JSON.stringify(referrals, null, 2));
        console.log('Referrals saved');
    } catch (err) {
        console.error('Error saving referrals:', err);
    }
}

async function loadBookings() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'bookings.json'), 'utf8');
        bookings = JSON.parse(data);
        console.log('Bookings loaded');
    } catch (err) {
        bookings = {};
        console.error('Error loading bookings.json:', err.code);
        await fs.writeFile(path.join(__dirname, 'bookings.json'), JSON.stringify({}, null, 2));
    }
}

async function saveBookings() {
    try {
        await fs.writeFile(path.join(__dirname, 'bookings.json'), JSON.stringify(bookings, null, 2));
        console.log('Bookings saved');
    } catch (err) {
        console.error('Error saving bookings:', err);
    }
}

async function loadFounders() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'founders.json'), 'utf8');
        founders = JSON.parse(data);
        console.log('Founders loaded');
    } catch (err) {
        founders = {};
        console.error('Error loading founders.json:', err.code);
        await fs.writeFile(path.join(__dirname, 'founders.json'), JSON.stringify(founders, null, 2));
    }
}

async function saveFounders() {
    try {
        await fs.writeFile(path.join(__dirname, 'founders.json'), JSON.stringify(founders, null, 2));
        console.log('Founders saved');
    } catch (err) {
        console.error('Error saving founders:', err);
    }
}

async function loadQuests() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'quests.json'), 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('Error loading quests:', err);
        return { quests: [] };
    }
}

async function saveQuests(questsData) {
    try {
        await fs.writeFile(path.join(__dirname, 'quests.json'), JSON.stringify(questsData, null, 2));
        console.log('Quests saved');
    } catch (err) {
        console.error('Error saving quests:', err);
    }
}

async function loadResponses() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'responses.json'), 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('Error loading responses:', err);
        return {};
    }
}

async function saveResponses(responsesData) {
    try {
        await fs.writeFile(path.join(__dirname, 'responses.json'), JSON.stringify(responsesData, null, 2));
        console.log('Responses saved');
    } catch (err) {
        console.error('Error saving responses:', err);
    }
}

// --- NEW: Function to load affiliate programs ---
async function loadAffiliatePrograms() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'affiliate-programs.json'), 'utf8');
        affiliatePrograms = JSON.parse(data).programs || [];
        console.log('Affiliate programs loaded');
    } catch (err) {
        console.error('Error loading affiliate-programs.json.', err);
        affiliatePrograms = [];
    }
}

// --- Initialize all data on startup ---
Promise.all([
    loadUsers(), 
    loadExperts(), 
    loadReferrals(), 
    loadBookings(), 
    loadFounders(),
    loadAffiliatePrograms() // Add new function to the startup process
]).then(() => {
    console.log('All initial data loaded');
}).catch(err => {
    console.error('Error during initial data load:', err);
});

// --- ROUTES ---

// --- Authentication Routes ---
app.get('/', (req,res) => res.redirect('/auth.html'));

app.get('/check-session', (req, res) => {
    if (req.session.userId) {
        res.json({ loggedIn: true, userId: req.session.userId, isAdmin: !!req.session.isAdmin });
    } else {
        res.json({ loggedIn: false });
    }
});

app.post('/signup', async (req, res) => {
    const { username, password, fullName, email } = req.body;
    if (!username || !password || !fullName || !email) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (username === ADMIN_USERNAME || users[username]) {
        return res.status(400).json({ error: 'Username already exists.' });
    }
    try {
        const passwordHash = await bcrypt.hash(password, saltRounds);
        users[username] = { passwordHash, fullName, email, blocked: false };
        await saveUsers();
        req.session.userId = username;
        req.session.isAdmin = false;
        req.session.lastActivity = Date.now();
        res.status(201).json({ message: 'Signed up', userId: username });
    } catch (err) {
        console.error('Error during signup:', err);
        res.status(500).json({error: 'Server error during registration.'});
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Credentials required' });
    }
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        req.session.userId = username;
        req.session.isAdmin = true;
        req.session.lastActivity = Date.now();
        return res.json({ message: 'Logged in', userId: username, isAdmin: true });
    }
    const user = users[username];
    if (!user || user.blocked) {
        return res.status(401).json({ error: 'Invalid credentials or account blocked' });
    }
    try {
        const match = await bcrypt.compare(password, user.passwordHash);
        if (match) {
            req.session.userId = username;
            req.session.isAdmin = false;
            req.session.lastActivity = Date.now();
            res.json({ message: 'Logged in', userId: username, isAdmin: false });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(500).json({error: 'Server error during login.'});
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Could not log out, please try again.'});
        }
        res.clearCookie('connect.sid'); 
        res.json({ message: 'Logged out' });
    });
});

// --- Quest Routes ---
// (Your existing quest routes like /quest-overview, /quests, etc. remain here)
app.get('/quest-overview', requireLogin, async (req, res) => {
    const userId = req.query.userId;
    if (!userId || userId !== req.session.userId) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }
    try {
        const overview = {
            totalEarnings: users[userId]?.totalEarnings || 0,
            questsCompleted: users[userId]?.completedQuests || 0,
            redeemableCodes: 0
        };
        res.json(overview);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch quest overview' });
    }
});

// --- Affiliate Routes ---
app.get('/affiliate-programs', requireLogin, (req, res) => {
    res.json({ programs: affiliatePrograms });
});

app.get('/generate-affiliate-link', requireLogin, (req, res) => {
    const { programId } = req.query;
    const userId = req.session.userId;
    if (!programId) {
        return res.status(400).json({ error: 'Program ID is required.' });
    }
    const affiliateLink = `http://localhost:${PORT}/track?programId=${programId}&affiliate_id=${encodeURIComponent(userId)}`;
    res.json({ affiliateLink });
});

// --- NEW: THE AFFILIATE CLICK TRACKING ENDPOINT ---
app.get('/track', (req, res) => {
    const { programId, affiliate_id } = req.query;
    if (!programId || !affiliate_id) {
        return res.status(400).send('<h1>Missing tracking information.</h1>');
    }
    const program = affiliatePrograms.find(p => p.id == programId);
    if (!program || !program.destinationUrl) {
        return res.status(404).send('<h1>Affiliate Program Not Found</h1>');
    }
    const clickData = {
        programId: parseInt(programId),
        programTitle: program.title,
        affiliateId: affiliate_id,
        timestamp: new Date().toISOString(),
        ipAddress: req.ip 
    };
    affiliateClicks.push(clickData);
    console.log('Affiliate Click Recorded:', clickData);
    res.redirect(program.destinationUrl);
});


// (The rest of your routes for experts, founders, admin actions, etc. would follow here)


// --- Static file routes ---
app.get('/home.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'home.html')));
app.get('/groweasy.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'groweasy.html')));
app.get('/affiliate.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'affiliate.html')));
app.get('/education.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'education.html')));
app.get('/founder.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'founder.html')));
app.get('/admin-experts.html', authMiddleware, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-experts.html')));
// ... other static routes ...

// Last middleware to run for activity tracking
app.use((req, res, next) => {
    if (req.session.userId) {
        req.session.lastActivity = Date.now();
    }
    next();
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

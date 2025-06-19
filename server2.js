require('dotenv').config();

const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const crypto = require('crypto'); // NEW: Add crypto for token generation
const app = express();
const PORT = process.env.PORT || 3000;

// --- NEW DEPENDENCY: Add multer for file uploads ---
// Make sure to install it by running: npm install multer
const multer = require('multer');

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password123';

const saltRounds = 10;

// --- Middleware Setup ---
app.use(cors());
const requireLogin = (req, res, next) => {
    console.log(`RequireLogin: Path=${req.path}, Session userId=${req.session.userId}, isAdmin=${req.session.isAdmin}`);
    if (!req.session.userId || (!users[req.session.userId] && !req.session.isAdmin) || (users[req.session.userId] && users[req.session.userId].blocked)) {
        console.log(`RequireLogin: No valid session for ${req.path}`);
        if (req.path === '/admin-experts.html') {
            console.log('Allowing access to admin-experts.html');
            return next();
        }
        return res.status(401).json({ error: 'Unauthorized, please log in' });
    }
    console.log(`RequireLogin: Valid session for ${req.path}`);
    next();
};

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-default-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 20 * 60 * 1000 }
}));

const authMiddleware = (req, res, next) => {
    console.log(`AuthMiddleware: Session userId=${req.session.userId}, isAdmin=${req.session.isAdmin}`);
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
        const base64Credentials = authHeader.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
        const [username, password] = credentials.split(':');
        if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
            console.log('AuthMiddleware: Basic Auth successful');
            req.session.userId = username;
            req.session.isAdmin = true;
            return next();
        }
        console.log('AuthMiddleware: Basic Auth failed');
    }
    if (!req.session.userId || (!req.session.isAdmin && req.session.userId !== ADMIN_USERNAME)) {
        console.log('AuthMiddleware: Unauthorized');
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
};

// Data management
let users = {};
let experts = {};
let referrals = {};
let bookings = {};
let founders = {};
let affiliatePrograms = [];
let affiliateClicks = [];
let conversions = [];


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
        console.error('Error loading experts:', err);
        experts = {};
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
        console.error('Error loading referrals:', err);
        referrals = {};
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
        console.error('Error loading bookings:', err);
        bookings = {};
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
        console.error('Error loading founders:', err);
        founders = {};
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

function parsePayout(payoutString) {
    if (typeof payoutString !== 'string') return 0;
    const match = payoutString.match(/\$?(\d+(\.\d+)?)/);
    if (match && match[1]) {
        return parseFloat(match[1]);
    }
    return 0;
}

async function loadAffiliatePrograms() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'affiliate-programs.json'), 'utf8');
        const affiliateData = JSON.parse(data);
        affiliatePrograms = (affiliateData.programs || []).map(p => ({
            ...p,
            payoutValue: parsePayout(p.payout)
        }));
        console.log('Affiliate programs loaded and processed');
    } catch (err) {
        if (err.code === 'ENOENT') {
            console.log('affiliate-programs.json not found.');
        } else {
            console.error('Error loading affiliate-programs.json:', err);
        }
        affiliatePrograms = [];
    }
}

async function loadConversions() {
    try {
        const data = await fs.readFile(path.join(__dirname, 'conversions.json'), 'utf8');
        conversions = JSON.parse(data);
        console.log('Conversions loaded');
    } catch (err) {
        if (err.code === 'ENOENT') {
            console.log('conversions.json not found, creating a new file.');
            await fs.writeFile(path.join(__dirname, 'conversions.json'), JSON.stringify([], null, 2));
        } else {
            console.error('Error loading conversions.json:', err);
        }
        conversions = [];
    }
}

async function saveConversions() {
    try {
        await fs.writeFile(path.join(__dirname, 'conversions.json'), JSON.stringify(conversions, null, 2));
        console.log('Conversions saved');
    } catch (err) {
        console.error('Error saving conversions:', err);
    }
}


// Initialize data
Promise.all([loadUsers(), loadExperts(), loadReferrals(), loadBookings(), loadFounders(), loadAffiliatePrograms(), loadConversions()]).then(() => {
    console.log('All data loaded');
}).catch(err => {
    console.error('Error initializing data:', err);
});

// Routes
app.get('/home.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'home.html')));

app.get('/check-session', async (req, res) => {
    console.log(`Check-session: userId=${req.session.userId}, isAdmin=${req.session.isAdmin}`);
    if (req.session.userId && (req.session.isAdmin || (users[req.session.userId] && !users[req.session.userId].blocked))) {
        res.json({ loggedIn: true, userId: req.session.userId, isAdmin: !!req.session.isAdmin });
    } else {
        console.log('Check-session: No valid session');
        res.json({ loggedIn: false });
    }
});

app.post('/signup', async (req, res) => {
    const { username, password, fullName, email } = req.body;
    console.log(`Signup attempt: username=${username}`);
    
    if (!username || !password || !fullName || !email) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (username === ADMIN_USERNAME) {
        return res.status(400).json({ error: 'Username reserved' });
    }
    if (users[username]) {
        return res.status(400).json({ error: users[username].blocked ? 'Username blocked' : 'Username exists' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: 'Invalid email' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
    
    try {
        const passwordHash = await bcrypt.hash(password, saltRounds);

        users[username] = {
            passwordHash,
            fullName,
            email,
            blocked: false,
            totalEarnings: 0,
            completedQuests: []
        };
        await saveUsers();
        
        req.session.userId = username;
        req.session.lastActivity = Date.now();
        
        res.status(201).json({ message: 'Signed up', userId: username });

    } catch (err) {
        console.error('Error during signup:', err);
        res.status(500).json({error: 'Server error during registration.'});
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Login attempt: username=${username}`);
    if (!username || !password) {
        return res.status(400).json({ error: 'Credentials required' });
    }

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        req.session.userId = username;
        req.session.isAdmin = true;
        req.session.lastActivity = Date.now();
        console.log('Admin login successful');
        return res.json({ message: 'Logged in', userId: username, isAdmin: true });
    }

    const user = users[username];

    if (!user) {
        console.log('Login failed: User not found');
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.blocked) {
        console.log('Login failed: Account blocked');
        return res.status(403).json({ error: 'Account blocked' });
    }

    try {
        const match = await bcrypt.compare(password, user.passwordHash);

        if (match) {
            req.session.userId = username;
            req.session.isAdmin = false;
            req.session.lastActivity = Date.now();
            console.log('User login successful');
            res.json({ message: 'Logged in', userId: username, isAdmin: false });
        } else {
            console.log('Login failed: Invalid credentials');
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({error: 'Server error during login.'});
    }
});

app.get('/logout', (req, res) => {
    console.log(`Logout: userId=${req.session.userId}`);
    req.session.destroy(() => {
        res.json({ message: 'Logged out' });
    });
});

// --- NEW: FORGOT AND RESET PASSWORD ROUTES ---
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const userEntry = Object.entries(users).find(([username, userData]) => userData.email === email);

    if (userEntry) {
        const [username, user] = userEntry;
        const token = crypto.randomBytes(20).toString('hex');
        
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        await saveUsers();

        const resetLink = `http://localhost:${PORT}/reset-password.html?token=${token}`;
        console.log(`Password reset link for ${username} (${email}): ${resetLink}`);
    } else {
        console.log(`Password reset attempt for non-existent email: ${email}`);
    }
    res.json({ message: 'If your email is registered, you will receive a password reset link shortly.' });
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    const userEntry = Object.entries(users).find(([username, userData]) => 
        userData.resetPasswordToken === token && userData.resetPasswordExpires > Date.now()
    );

    if (!userEntry) {
        return res.status(400).json({ error: 'Password reset token is invalid or has expired.' });
    }

    if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    const [username, user] = userEntry;
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);
    
    user.passwordHash = passwordHash;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await saveUsers();

    res.json({ message: 'Your password has been updated successfully. You can now log in.' });
});


// ==================================================================
// === ROUTES ADDED FOR PROFILE PAGE ================================
// ==================================================================

// Endpoint to get all necessary data for the profile page
app.get('/api/profile/:userId', requireLogin, (req, res) => {
    const { userId } = req.params;

    if (userId !== req.session.userId && !req.session.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    const user = users[userId];
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    const totalEarnings = user.totalEarnings || 0;
    const questsCompleted = user.completedQuests ? user.completedQuests.length : 0;
    
    const userConversions = conversions.filter(c => c.affiliateId === userId);
    const referralsCount = userConversions.length;
    const referralEarnings = userConversions.reduce((sum, conv) => sum + (conv.payout || 0), 0);

    const loginStreak = user.loginStreak || 5; 

    const earningsChartData = Array.from({length: 7}, (_, i) => {
        const dayEarning = (totalEarnings / (Math.random() * 10 + 7)) * (i + 1);
        return parseFloat(dayEarning.toFixed(2));
    });

    const recentActivity = [
        { icon: 'fa-check-circle', color: 'primary', text: `Completed "Crypto Basics" quest`, detail: `+$${(user.completedQuests && user.completedQuests.length > 0 ? '5.00' : '0.00')} • 2 hours ago` },
        { icon: 'fa-user-plus', color: 'green-500', text: `A new user joined via your referral!`, detail: `+${referralEarnings.toFixed(2)} • 5 hours ago` },
        { icon: 'fa-medal', color: 'yellow-500', text: `Level up! You're now Level 5`, detail: `+$2.00 bonus • Yesterday` },
    ];

    res.json({
        fullName: user.fullName,
        username: userId,
        level: 5,
        title: "Crypto Apprentice",
        avatar: user.avatar || 'https://www.gravatar.com/avatar/?d=mp',
        totalEarnings: totalEarnings.toFixed(2),
        questsCompleted,
        referralsCount,
        referralEarnings: referralEarnings.toFixed(2),
        loginStreak,
        earningsChartData,
        recentActivity
    });
});

// Endpoint to handle profile picture upload
const upload = multer({ dest: 'public/uploads/' });

app.post('/api/user/upload-picture', requireLogin, upload.single('profilePicture'), async (req, res) => {
    const userId = req.session.userId;
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    const user = users[userId];
    if (!user) {
        return res.status(404).json({ error: 'User not found.' });
    }

    const filePath = `/uploads/${req.file.filename}`;
    user.avatar = filePath;
    await saveUsers();

    res.json({ message: 'Profile picture updated successfully.', filePath });
});

// ==================================================================
// === END OF NEW ROUTES ============================================
// ==================================================================


app.get('/quest-overview', requireLogin, async (req, res) => {
    const userId = req.query.userId;
    console.log(`Quest-overview: userId=${userId}, session userId=${req.session.userId}`);
    if (!userId || userId !== req.session.userId || !users[userId]) {
        console.log('Quest-overview: Invalid or missing userId');
        return res.status(400).json({ error: 'Invalid user ID' });
    }
    try {
        const user = users[userId];
        const completedQuests = Array.isArray(user.completedQuests) ? user.completedQuests : [];
        
        const overview = {
            totalEarnings: user.totalEarnings || 0,
            questsCompleted: completedQuests,
            redeemableCodes: 3
        };
        res.json(overview);
    } catch (err) {
        console.error('Quest-overview error:', err);
        res.status(500).json({ error: 'Failed to fetch quest overview' });
    }
});


app.get('/quests', requireLogin, async (req, res) => {
    try {
        const questsData = await loadQuests();
        res.json(questsData);
    } catch (err) {
        console.error('Error reading quests:', err);
        res.json({ quests: [] });
    }
});

app.post('/quests', authMiddleware, async (req, res) => {
    const { action, id, title, description, reward, status, endTime, participants, quizPage, questions } = req.body;
    try {
        const questsData = await loadQuests();
        if (action === 'delete') {
            questsData.quests = questsData.quests.filter(q => q.id != id);
        } else {
            const newId = action === 'edit' ? id : questsData.quests.length + 1;
            const questIndex = questsData.quests.findIndex(q => q.id == id);
            const quest = {
                id: newId,
                title,
                description,
                reward,
                status,
                endTime,
                startTime: new Date().toISOString(),
                participants: participants || 0,
                quizPage,
                questions: questions || [],
                referralLink: `http://localhost:${PORT}/referral?questId=${newId}`
            };
            if (questIndex >= 0) {
                questsData.quests[questIndex] = quest;
            } else {
                questsData.quests.push(quest);
            }
        }
        await saveQuests(questsData);
        res.json({ message: action === 'delete' ? 'Quest deleted' : action === 'edit' ? 'Quest updated' : 'Quest added' });
    } catch (err) {
        console.error('Error managing quest:', err);
        res.status(500).json({ error: 'Failed to manage quest' });
    }
});

app.get('/quests/:questId/questions', requireLogin, async (req, res) => {
    const { questId } = req.params;
    try {
        const questsData = await loadQuests();
        const quest = questsData.quests.find(q => q.id == questId);
        if (!quest) return res.status(404).json({ error: 'Quest not found' });
        res.json({ questions: quest.questions || [] });
    } catch (err) {
        console.error('Error fetching questions:', err);
        res.status(500).json({ error: 'Failed to fetch questions' });
    }
});

app.post('/quests/:questId/questions', authMiddleware, async (req, res) => {
    const { questId } = req.params;
    const { id, type, text, options, correctAnswer } = req.body;
    try {
        const questsData = await loadQuests();
        const quest = questsData.quests.find(q => q.id == questId);
        if (!quest) return res.status(404).json({ error: 'Quest not found' });

        if (!quest.questions) quest.questions = [];
        const questionId = id || `q${quest.questions.length + 1}`;
        const questionIndex = quest.questions.findIndex(q => q.id === id);

        let question = { id: questionId, type, text };
        if (type === 'multiple-choice') {
            if (!options || !correctAnswer || !options.includes(correctAnswer)) {
                return res.status(400).json({ error: 'Invalid options or correct answer' });
            }
            question.options = options;
            question.correctAnswer = correctAnswer;
        }

        if (questionIndex >= 0) {
            quest.questions[questionIndex] = question;
        } else {
            quest.questions.push(question);
        }

        await saveQuests(questsData);
        res.json({ message: id ? 'Question updated' : 'Question added', id: questionId });
    } catch (err) {
        console.error('Error managing question:', err);
        res.status(500).json({ error: 'Failed to manage question' });
    }
});

app.delete('/quests/:questId/questions/:questionId', authMiddleware, async (req, res) => {
    const { questId, questionId } = req.params;
    try {
        const questsData = await loadQuests();
        const quest = questsData.quests.find(q => q.id == questId);
        if (!quest) return res.status(404).json({ error: 'Quest not found' });

        quest.questions = quest.questions.filter(q => q.id !== questionId);
        await saveQuests(questsData);
        res.json({ message: 'Question deleted' });
    } catch (err) {
        console.error('Error deleting question:', err);
        res.status(500).json({ error: 'Failed to delete question' });
    }
});

app.post('/submit-quiz/:questId', requireLogin, async (req, res) => {
    const questId = parseInt(req.params.questId);
    const userId = req.session.userId;
    const user = users[userId];

    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    if (!Array.isArray(user.completedQuests)) {
        user.completedQuests = [];
    }
    if (user.totalEarnings === undefined) {
        user.totalEarnings = 0;
    }
    if (user.completedQuests.some(q => q.id === questId)) {
        return res.status(400).json({ error: "You have already completed this quest." });
    }

    try {
        const questsData = await loadQuests();
        const quest = questsData.quests.find(q => q.id === questId);

        if (!quest) {
            return res.status(404).json({ error: 'Quest not found' });
        }

        const rewardValue = parseFloat(quest.reward.replace(/[^0-9.-]+/g, "")) || 0;
        user.totalEarnings += rewardValue;
        
        const completionRecord = {
            id: questId,
            completedAt: new Date().toISOString()
        };
        user.completedQuests.push(completionRecord);

        await saveUsers();

        res.json({ message: "Quest completed successfully!", reward: quest.reward });
    } catch (err) {
        console.error('Error submitting quiz:', err);
        res.status(500).json({ error: 'Failed to submit quiz' });
    }
});


app.get('/quests/:questId/responses', authMiddleware, async (req, res) => {
    const { questId } = req.params;
    try {
        const responsesData = await loadResponses();
        res.json(responsesData[questId] || {});
    } catch (err) {
        console.error('Error fetching responses:', err);
        res.status(500).json({ error: 'Failed to fetch responses' });
    }
});

app.get('/referrals', requireLogin, async (req, res) => {
    const userId = req.query.userId;
    console.log(`Referrals: userId=${userId}, session userId=${req.session.userId}`);
    if (!userId || userId !== req.session.userId) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }
    try {
        const userReferrals = {};
        for (const questId in referrals) {
            userReferrals[questId] = referrals[questId].referrers[userId] || 0;
        }
        res.json(userReferrals);
    } catch (err) {
        console.error('Referrals error:', err);
        res.json({});
    }
});

app.get('/generate-referral-link', requireLogin, async (req, res) => {
    const { questId, userId } = req.query;
    console.log(`Generate-referral-link: questId=${questId}, userId=${userId}`);
    if (!questId || !userId || userId !== req.session.userId) {
        return res.status(400).json({ error: 'Invalid quest or user ID' });
    }
    const referralLink = `http://localhost:${PORT}/referral?questId=${questId}&referrerId=${encodeURIComponent(userId)}`;
    res.json({ referralLink });
});

app.get('/referral', async (req, res) => {
    const questId = parseInt(req.query.questId);
    const referrerId = req.query.referrerId;
    try {
        const data = await fs.readFile(path.join(__dirname, 'quests.json'), 'utf8');
        const quests = JSON.parse(data).quests;
        const quest = quests.find(q => q.id === questId);
        if (!quest) return res.status(404).json({ error: 'Quest not found' });
        if (!referrals[questId]) referrals[questId] = { total: 0, referrers: {} };
        referrals[questId].total = (referrals[questId].total || 0) + 1;
        if (referrerId && !req.session.referredQuests?.includes(questId)) {
            referrals[questId].referrers[referrerId] = (referrals[questId].referrers[referrerId] || 0) + 1;
            req.session.referredQuests = req.session.referredQuests || [];
            req.session.referredQuests.push(questId);
        }
        await saveReferrals();
        res.redirect(quest.quizPage);
    } catch (err) {
        console.error('Referral error:', err);
        res.status(500).json({ error: 'Failed to process referral' });
    }
});

app.get('/experts', async (req, res) => {
    try {
        const data = await fs.readFile(path.join(__dirname, 'experts.json'), 'utf8');
        res.json(JSON.parse(data));
    } catch (err) {
        console.error('Error reading experts:', err);
        res.json({});
    }
});

app.post('/experts', authMiddleware, async (req, res) => {
    try {
        const { action, id, name, title, bio, rate, avatar, socials, portfolio, hidden } = req.body;
        let expertsData = {};
        try {
            const data = await fs.readFile(path.join(__dirname, 'experts.json'), 'utf8');
            expertsData = JSON.parse(data);
        } catch (err) {
            expertsData = {};
        }
        if (action === 'delete') {
            if (!expertsData[id]) return res.status(404).json({ error: 'Expert not found' });
            delete expertsData[id];
        } else {
            const newId = action === 'edit' ? id : `expert-${Object.keys(expertsData).length + 1}`;
            expertsData[newId] = {
                id: newId,
                name,
                title,
                bio,
                rate,
                avatar: avatar || 'https://randomuser.me/api/portraits/lego/1.jpg',
                socials: socials || [],
                portfolio: portfolio || [],
                hidden: hidden !== undefined ? hidden : false
            };
        }
        await fs.writeFile(path.join(__dirname, 'experts.json'), JSON.stringify(expertsData, null, 2));
        res.json({ message: action === 'delete' ? 'Expert deleted' : action === 'edit' ? 'Expert updated' : 'Expert added' });
    } catch (err) {
        console.error('Error managing expert:', err);
        res.status(500).json({ error: 'Failed to manage expert' });
    }
});

app.get('/expert/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const data = await fs.readFile(path.join(__dirname, 'experts.json'), 'utf8');
        const expertsData = JSON.parse(data);
        const expert = expertsData[id];
        if (!expert) return res.status(404).json({ error: 'Expert not found' });
        res.json(expert);
    } catch (err) {
        console.error('Error fetching expert:', err);
        res.status(500).json({ error: 'Failed to fetch expert' });
    }
});

app.post('/book-expert', requireLogin, async (req, res) => {
    try {
        const { expertId, reason, preferredDate } = req.body;
        if (!expertId || !reason || !preferredDate) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        const expertsData = JSON.parse(await fs.readFile(path.join(__dirname, 'experts.json'), 'utf8'));
        if (!expertsData[expertId]) return res.status(404).json({ error: 'Expert not found' });
        const bookingId = `booking-${Object.keys(bookings).length + 1}`;
        bookings[bookingId] = {
            id: bookingId,
            userId: req.session.userId,
            expertId,
            reason,
            preferredDate,
            status: 'pending'
        };
        await saveBookings();
        res.json({ success: true, message: 'Booking submitted' });
    } catch (err) {
        console.error('Booking error:', err);
        res.status(500).json({ error: 'Failed to submit booking' });
    }
});

app.get('/affiliate-programs', async (req, res) => {
    res.json({ programs: affiliatePrograms });
});

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
        type: 'click',
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

app.post('/api/affiliate/conversion', async (req, res) => {
    const { programId, affiliateId, conversionValue } = req.body;
    if (!programId || !affiliateId) {
        return res.status(400).json({ error: 'Missing conversion information.' });
    }

    const program = affiliatePrograms.find(p => p.id == programId);
    if (!program) {
        return res.status(404).json({ error: 'Program not found.' });
    }

    const conversionData = {
        type: 'conversion',
        programId: parseInt(programId),
        programTitle: program.title,
        affiliateId,
        payout: program.payoutValue || 0,
        value: conversionValue || 0,
        timestamp: new Date().toISOString(),
    };

    conversions.push(conversionData);
    await saveConversions();
    console.log('Conversion Recorded:', conversionData);

    res.status(201).json({ message: 'Conversion recorded successfully.' });
});

app.get('/api/affiliate/stats', requireLogin, (req, res) => {
    const affiliateId = req.session.userId;
    const { range } = req.query;

    let sinceDate = new Date(0);
    if (range === '7days') {
        sinceDate = new Date();
        sinceDate.setDate(sinceDate.getDate() - 7);
    } else if (range === '30days') {
        sinceDate = new Date();
        sinceDate.setMonth(sinceDate.getMonth() - 1);
    }

    const userClicks = affiliateClicks.filter(c =>
        c.affiliateId === affiliateId && new Date(c.timestamp) >= sinceDate
    );

    const userConversions = conversions.filter(c =>
        c.affiliateId === affiliateId && new Date(c.timestamp) >= sinceDate
    );

    const totalEarnings = userConversions.reduce((sum, conv) => sum + (conv.payout || 0), 0);

    res.json({
        totalClicks: userClicks.length,
        totalConversions: userConversions.length,
        totalEarnings: parseFloat(totalEarnings.toFixed(2)),
    });
});

app.get('/api/affiliate/history', requireLogin, (req, res) => {
    const affiliateId = req.session.userId;

    const userClicks = affiliateClicks
        .filter(c => c.affiliateId === affiliateId)
        .map(c => ({...c, type: 'Click', reward: 'N/A', status: 'Tracked' }));

    const userConversions = conversions
        .filter(c => c.affiliateId === affiliateId)
        .map(c => ({ ...c, type: 'Conversion', reward: `$${(c.payout || 0).toFixed(2)}`, status: 'Completed' }));

    const combinedHistory = [...userClicks, ...userConversions];
    combinedHistory.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json(combinedHistory);
});


app.get('/education-content', async (req, res) => {
    try {
        const data = await fs.readFile(path.join(__dirname, 'education-content.json'), 'utf8');
        res.json(JSON.parse(data));
    } catch (err) {
        console.error('Error reading education content:', err);
        res.json({ categories: [] });
    }
});

app.get('/products', async (req, res) => {
    try {
        const data = await fs.readFile(path.join(__dirname, 'products.json'), 'utf8');
        res.json(JSON.parse(data));
    } catch (err) {
        console.error('Error reading products:', err);
        res.json([]);
    }
});

app.get('/groweasy.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'groweasy.html')));
app.get('/affiliate.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'affiliate.html')));
app.get('/education.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'education.html')));
app.get('/founder.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'founder.html')));
app.get('/admin-experts.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-experts.html')));

app.post('/block-user', authMiddleware, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    if (!users[username]) return res.status(404).json({ error: 'User not found' });
    users[username].blocked = true;
    await saveUsers();
    const sessionStore = req.sessionStore;
    sessionStore.all((err, sessions) => {
        if (err) return res.status(500).json({ error: 'Session error' });
        for (const sessionId in sessions) {
            if (sessions[sessionId].userId === username) {
                sessionStore.destroy(sessionId, err => err && console.error('Session destroy error:', err));
            }
        }
        res.json({ message: `User ${username} blocked` });
    });
});

app.post('/delete-user', authMiddleware, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    if (!users[username]) return res.status(404).json({ error: 'User not found' });
    delete users[username];
    await saveUsers();
    const sessionStore = req.sessionStore;
    sessionStore.all((err, sessions) => {
        if (err) return res.status(500).json({ error: 'Session error' });
        for (const sessionId in sessions) {
            if (sessions[sessionId].userId === username) {
                sessionStore.destroy(sessionId, err => err && console.error('Session destroy error:', err));
            }
        }
        res.json({ message: `User ${username} deleted` });
    });
});

app.get('/total-users', (req, res) => {
    const totalUsers = Object.keys(users).length + (req.session.isAdmin ? 1 : 0);
    res.json({ totalUsers });
});

app.get('/online-users', (req, res) => {
    const now = Date.now();
    const sessionTimeout = 20 * 60 * 1000;
    let onlineUsers = req.session.isAdmin ? 1 : 0;
    const sessionStore = req.sessionStore;
    sessionStore.all((err, sessions) => {
        if (err) {
            console.error('Session retrieval error:', err);
            return res.status(500).json({ error: 'Session error' });
        }
        for (const sessionId in sessions) {
            const session = sessions[sessionId];
            if (session.userId && session.lastActivity && now - session.lastActivity < sessionTimeout && !session.isAdmin) {
                onlineUsers++;
            }
        }
        res.json({ onlineUsers });
    });
});

app.get('/founders', async (req, res) => {
    try {
        const data = await fs.readFile(path.join(__dirname, 'founders.json'), 'utf8');
        res.json(JSON.parse(data));
    } catch (err) {
        console.error('Error reading founders:', err);
        res.json({});
    }
});

app.get('/founder/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const data = await fs.readFile(path.join(__dirname, 'founders.json'), 'utf8');
        const foundersData = JSON.parse(data);
        const founder = foundersData[id];
        if (!founder) return res.status(404).json({ error: 'Founder not found' });
        res.json(founder);
    } catch (err) {
        console.error('Error fetching founder:', err);
        res.status(500).json({ error: 'Failed to fetch founder' });
    }
});

app.post('/book-founder', requireLogin, async (req, res) => {
    try {
        const { founderId, reason, preferredDate } = req.body;
        if (!founderId || !reason || !preferredDate) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        const foundersData = JSON.parse(await fs.readFile(path.join(__dirname, 'founders.json'), 'utf8'));
        if (!foundersData[founderId]) return res.status(404).json({ error: 'Founder not found' });
        const bookingId = `booking-${Object.keys(bookings).length + 1}`;
        bookings[bookingId] = {
            id: bookingId,
            userId: req.session.userId,
            founderId,
            reason,
            preferredDate,
            status: 'pending'
        };
        await saveBookings();
        res.json({ success: true, message: 'Booking submitted' });
    } catch (err) {
        console.error('Booking error:', err);
        res.status(500).json({ error: 'Failed to submit booking' });
    }
});

app.post('/founders', authMiddleware, async (req, res) => {
    try {
        const { action, id, name, title, bio, rate, avatar, socials, portfolio, hidden } = req.body;
        let foundersData = {};
        try {
            const data = await fs.readFile(path.join(__dirname, 'founders.json'), 'utf8');
            foundersData = JSON.parse(data);
        } catch (err) {
            foundersData = {};
        }
        if (action === 'delete') {
            if (!foundersData[id]) return res.status(404).json({ error: 'Founder not found' });
            delete foundersData[id];
        } else {
            const newId = action === 'edit' ? id : `founder-${Object.keys(foundersData).length + 1}`;
            foundersData[newId] = {
                id: newId,
                name,
                title,
                bio,
                rate,
                avatar: avatar || 'https://randomuser.me/api/portraits/lego/1.jpg',
                socials: socials || [],
                portfolio: portfolio || [],
                hidden: hidden !== undefined ? hidden : false
            };
        }
        await fs.writeFile(path.join(__dirname, 'founders.json'), JSON.stringify(foundersData, null, 2));
        res.json({ message: action === 'delete' ? 'Founder deleted' : action === 'edit' ? 'Founder updated' : 'Founder added' });
    } catch (err) {
        console.error('Error managing founder:', err);
        res.status(500).json({ error: 'Failed to manage founder' });
    }
});

app.use((req, res, next) => {
    if (req.session.userId) req.session.lastActivity = Date.now();
    next();
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
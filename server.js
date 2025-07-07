require('dotenv').config();

const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// Tell Express to trust the proxy that Render uses
app.set('trust proxy', 1);

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const saltRounds = 10;

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

(async () => {
  try {
    await pool.query('SET search_path TO public');
    console.log('Search path set to public ✅');
  } catch (err) {
    console.error('Failed to set search_path:', err);
  }
})();

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 20 * 60 * 1000,
        secure: true, 
        httpOnly: true, 
        sameSite: 'lax'
    }
}));

// Middleware functions (requireLogin, requireAdmin, etc.)
const requireLogin = async (req, res, next) => {
    if (!req.session.userId) {
        if (req.headers.accept && req.headers.accept.includes('text/html')) {
            return res.redirect('/auth.html');
        }
        return res.status(401).json({ error: 'Unauthorized, please log in' });
    }
    if (req.session.isAdmin) {
        if (req.session.userId === process.env.ADMIN_USERNAME) {
            return next(); 
        } else {
            return res.status(401).json({ error: 'Unauthorized' });
        }
    }
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [req.session.userId]);
        const user = result.rows[0];
        if (!user || user.blocked) {
            return res.status(401).json({ error: 'Unauthorized or account blocked' });
        }
        req.user = user; 
        next();
    } catch (err) {
        console.error('Error in requireLogin middleware', err);
        return res.status(500).json({ error: 'Server error' });
    }
};

const requireAdmin = (req, res, next) => {
    if (req.session.userId && req.session.isAdmin && req.session.userId === process.env.ADMIN_USERNAME) {
        return next();
    }
    return res.status(403).json({ error: 'Forbidden: Requires admin privileges' });
};

function parsePayout(payoutString) {
    if (typeof payoutString !== 'string') return 0;
    const match = payoutString.match(/\$?(\d+(\.\d+)?)/);
    return (match && match[1]) ? parseFloat(match[1]) : 0;
}

// --- Routes ---

// FIX: Explicitly set index.html as the default page for the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- NEW BUILD PAGE API ENDPOINTS ---
app.get('/api/build-data', requireLogin, async (req, res) => {
    try {
        const data = await fs.readFile(path.join(__dirname, 'public', 'build-data.json'), 'utf8');
        res.json(JSON.parse(data));
    } catch (err) {
        console.error('Error reading build data:', err);
        res.status(500).json({ error: 'Failed to fetch build data' });
    }
});

app.get('/api/experts', requireLogin, async (req, res) => {
    try {
        const data = await fs.readFile(path.join(__dirname, 'public', 'build-data.json'), 'utf8');
        const jsonData = JSON.parse(data);
        res.json(jsonData.expertsData);
    } catch (err) {
        console.error('Error reading experts data:', err);
        res.status(500).json({ error: 'Failed to fetch experts data' });
    }
});
// --- END NEW BUILD PAGE API ENDPOINTS ---


// --- NEW JOBS API ENDPOINTS ---
app.get('/api/jobs', requireLogin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM affiliate_programs ORDER BY id');
        
        const jobs = result.rows.map(program => {
            const requirements = [];
            if (program.guidelines) requirements.push(program.guidelines);
            if (program.pros && program.pros.length > 0) requirements.push(...program.pros.map(p => `Pro: ${p}`));
            if (program.cons && program.cons.length > 0) requirements.push(...program.cons.map(c => `Con: ${c}`));

            const categorySlug = program.category.toLowerCase().replace(/\s+/g, '-');
            
            const titleMatch = program.title.match(/(\d+)/);
            const target = titleMatch ? parseInt(titleMatch[0], 10) : 1;

            return {
                id: program.id,
                title: program.title,
                category: categorySlug,
                payment: parsePayout(program.payout),
                description: program.details,
                requirements: requirements,
                target: target,
                destinationUrl: program.destination_url
            };
        });
        
        res.json({ jobs });
    } catch (err) {
        console.error('Error fetching jobs:', err);
        res.status(500).json({ error: 'Failed to fetch jobs' });
    }
});

app.post('/api/jobs/:jobId/complete', requireLogin, async (req, res) => {
    const { jobId } = req.params;
    const { submissionLink } = req.body;
    const userDbId = req.user.id;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const jobResult = await client.query('SELECT * FROM affiliate_programs WHERE id = $1', [jobId]);
        const job = jobResult.rows[0];

        if (!job) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Job not found.' });
        }

        const payoutAmount = parsePayout(job.payout);
        
        await client.query('UPDATE users SET points = points + $1 WHERE id = $2', [payoutAmount, userDbId]);

        if (job.category.toLowerCase().includes('video') || job.category.toLowerCase().includes('post')) {
            console.log(`User ${req.user.username} submitted link for job ${jobId}: ${submissionLink}`);
        }

        await client.query('COMMIT');
        res.json({ success: true, message: `Job completed! $${payoutAmount} awarded.` });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error completing job:', err);
        res.status(500).json({ error: 'Failed to complete job.' });
    } finally {
        client.release();
    }
});
// --- END NEW JOBS API ENDPOINTS ---


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
    if (username === ADMIN_USERNAME) {
        return res.status(400).json({ error: 'Username reserved' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: 'Invalid email' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
    
    try {
        const existingUserResult = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (existingUserResult.rows.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        const passwordHash = await bcrypt.hash(password, saltRounds);
        const newUserQuery = `INSERT INTO users (username, email, password_hash, full_name) VALUES ($1, $2, $3, $4) RETURNING id, username;`;
        const newUserResult = await pool.query(newUserQuery, [username, email, passwordHash, fullName]);
        const { id, username: newUsername } = newUserResult.rows[0];

        req.session.userId = newUsername;
        req.session.isAdmin = false;
        req.session.lastActivity = Date.now();
        
        res.status(201).json({ message: 'Signed up', userId: newUsername });
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

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (user.blocked) {
            return res.status(403).json({ error: 'Account blocked' });
        }

        const match = await bcrypt.compare(password, user.password_hash);

        if (match) {
            const today = new Date();
            const lastLogin = user.last_login ? new Date(user.last_login) : null;
            let newStreak = 1;

            if (lastLogin) {
                const todayMidnight = new Date(today).setHours(0, 0, 0, 0);
                const lastLoginMidnight = new Date(lastLogin).setHours(0, 0, 0, 0);
                const diffDays = (todayMidnight - lastLoginMidnight) / (1000 * 60 * 60 * 24);
                if (diffDays === 1) newStreak = (user.login_streak || 0) + 1;
                else if (diffDays > 1) newStreak = 1;
                else newStreak = user.login_streak || 1;
            }
            await pool.query('UPDATE users SET last_login = NOW(), login_streak = $1 WHERE id = $2', [newStreak, user.id]);
            
            req.session.userId = username;
            req.session.isAdmin = false;
            req.session.lastActivity = Date.now();
            res.json({ message: 'Logged in', userId: username, isAdmin: false });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({error: 'Server error during login.'});
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.json({ message: 'Logged out' }));
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (user) {
            const token = crypto.randomBytes(20).toString('hex');
            const expires = new Date(Date.now() + 3600000); // 1 hour
            await pool.query('UPDATE users SET reset_password_token = $1, reset_password_expires = $2 WHERE id = $3', [token, expires, user.id]);
            const resetLink = `${process.env.BASE_URL}/reset-password.html?token=${token}`;
            console.log(`Password reset link for ${user.username} (${email}): ${resetLink}`);
        }
    } catch (err) {
        console.error('Forgot password error:', err);
    }
    res.json({ message: 'If your email is registered, you will receive a password reset link shortly.' });
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: 'Token and a valid new password are required.' });
    }
    try {
        const result = await pool.query('SELECT * FROM users WHERE reset_password_token = $1 AND reset_password_expires > NOW()', [token]);
        const user = result.rows[0];
        if (!user) {
            return res.status(400).json({ error: 'Password reset token is invalid or has expired.' });
        }
        const passwordHash = await bcrypt.hash(newPassword, saltRounds);
        await pool.query('UPDATE users SET password_hash = $1, reset_password_token = NULL, reset_password_expires = NULL WHERE id = $2', [passwordHash, user.id]);
        res.json({ message: 'Your password has been updated successfully. You can now log in.' });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ error: 'Server error.' });
    }
});

app.get('/api/profile/:userId', requireLogin, async (req, res) => {
    const { userId } = req.params;

    if (userId !== req.session.userId && !req.session.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [userId]);
        const user = userResult.rows[0];
        if (!user) return res.status(404).json({ error: 'User not found' });

        const completedQuestsResult = await pool.query('SELECT quest_id FROM user_quests WHERE user_id = $1', [user.id]);
        const completedQuestIds = completedQuestsResult.rows.map(r => r.quest_id);

        const activeQuestsResult = await pool.query('SELECT COUNT(*) FROM quests WHERE status = $1 AND id NOT IN (SELECT quest_id FROM user_quests WHERE user_id = $2)', ['Available', user.id]);
        const referralsResult = await pool.query('SELECT COUNT(*) FROM conversions WHERE affiliate_username = $1', [user.username]);
        const referralEarningsResult = await pool.query('SELECT SUM(payout_amount) as total FROM conversions WHERE affiliate_username = $1', [user.username]);
        
        const historyQuery = `
            (SELECT
                'Completed quest: ''' || q.title || '''' AS details,
                parse_payout(q.reward) AS amount,
                uq.completed_at AS created_at,
                'credit' as type
            FROM user_quests uq
            JOIN quests q ON uq.quest_id = q.id
            WHERE uq.user_id = $1)
            UNION ALL
            (SELECT
                'Affiliate conversion for ''' || ap.title || '''' AS details,
                c.payout_amount AS amount,
                c.timestamp AS created_at,
                'credit' as type
            FROM conversions c
            JOIN affiliate_programs ap ON c.program_id = ap.id
            WHERE c.affiliate_username = $2)
            UNION ALL
            (SELECT
                'Withdrew funds' AS details,
                rc.amount AS amount,
                rc.created_at AS created_at,
                'debit' as type
            FROM redeemable_codes rc
            WHERE rc.user_id = $1)
            ORDER BY created_at DESC
            LIMIT 10;
        `;
        const recentActivityResult = await pool.query(historyQuery, [user.id, user.username]);

        const earningsHistoryResult = await pool.query(`
            SELECT TO_CHAR(date_trunc('day', d), 'Mon DD') AS label, COALESCE(SUM(amount), 0) AS value
            FROM GENERATE_SERIES(CURRENT_DATE - INTERVAL '6 days', CURRENT_DATE, '1 day'::interval) d
            LEFT JOIN (
                SELECT completed_at AS earned_at, (SELECT parse_payout(reward) FROM quests q WHERE q.id = uq.quest_id) AS amount FROM user_quests uq WHERE uq.user_id = $1
                UNION ALL
                SELECT timestamp AS earned_at, payout_amount AS amount FROM conversions WHERE affiliate_username = $2
            ) earnings ON date_trunc('day', d) = date_trunc('day', earnings.earned_at)
            GROUP BY 1 ORDER BY 1;
        `, [user.id, user.username]);

        res.json({
            fullName: user.full_name,
            username: user.username,
            avatar: user.avatar,
            level: Math.floor((user.points || 0) / 100) + 1,
            title: "Crypto Apprentice",
            totalEarnings: parseFloat(user.points) || 0,
            questsCompleted: completedQuestIds.length,
            referralsCount: parseInt(referralsResult.rows[0].count, 10),
            referralEarnings: parseFloat(referralEarningsResult.rows[0].total) || 0,
            loginStreak: user.login_streak || 0,
            activeQuestsCount: parseInt(activeQuestsResult.rows[0].count, 10),
            earningsChartData: {
                labels: earningsHistoryResult.rows.map(r => r.label),
                data: earningsHistoryResult.rows.map(r => r.value),
            },
            recentActivity: recentActivityResult.rows,
            completedQuestIds: completedQuestIds
        });
    } catch (err) {
        console.error('Error fetching profile data:', err);
        res.status(500).json({ error: 'Failed to fetch profile data.' });
    }
});

app.get('/api/profile/:userId/earnings-history', requireLogin, async (req, res) => {
    const { userId } = req.params;
    const { range } = req.query; 

    let interval, seriesStart;
    switch(range) {
        case '1m': interval = '30 days'; seriesStart = `CURRENT_DATE - INTERVAL '${interval}'`; break;
        case '6m': interval = '6 months'; seriesStart = `CURRENT_DATE - INTERVAL '${interval}'`; break;
        case '1y': interval = '1 year'; seriesStart = `CURRENT_DATE - INTERVAL '${interval}'`; break;
        case 'all': interval = null; seriesStart = `(SELECT MIN(created_at) FROM users WHERE username = $2)`; break;
        default: interval = '6 days'; seriesStart = `CURRENT_DATE - INTERVAL '${interval}'`; break;
    }

    try {
        const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [userId]);
        if (userResult.rows.length === 0) return res.status(404).json({error: "User not found"});
        const userDbId = userResult.rows[0].id;
        
        const query = `
            SELECT TO_CHAR(date_trunc('day', d), 'Mon DD, YY') AS label, COALESCE(SUM(amount), 0) AS value
            FROM GENERATE_SERIES(${seriesStart}, CURRENT_DATE, '1 day'::interval) d
            LEFT JOIN (
                SELECT completed_at AS earned_at, (SELECT parse_payout(reward) FROM quests q WHERE q.id = uq.quest_id) AS amount FROM user_quests uq WHERE uq.user_id = $1
                UNION ALL
                SELECT timestamp AS earned_at, payout_amount AS amount FROM conversions WHERE affiliate_username = $2
            ) earnings ON date_trunc('day', d) = date_trunc('day', earnings.earned_at)
            GROUP BY 1 ORDER BY 1;
        `;
        const earningsResult = await pool.query(query, [userDbId, userId]);
        res.json({
            labels: earningsResult.rows.map(r => r.label),
            data: earningsResult.rows.map(r => parseFloat(r.value))
        });
    } catch(err) {
        console.error("Error fetching earnings history:", err);
        res.status(500).json({error: 'Failed to fetch earnings history'});
    }
});

const upload = multer({ dest: 'public/uploads/' });
app.post('/api/user/upload-picture', requireLogin, upload.single('profilePicture'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }
    const filePath = `/uploads/${req.file.filename}`;
    try {
        await pool.query('UPDATE users SET avatar = $1 WHERE id = $2', [filePath, req.user.id]);
        res.json({ message: 'Profile picture updated successfully.', filePath });
    } catch (err) {
        console.error('Error uploading profile picture:', err);
        await fs.unlink(path.join(__dirname, 'public', filePath)).catch(e => console.error("Failed to cleanup file", e));
        res.status(500).json({ error: 'Failed to update profile picture' });
    }
});

app.get('/quest-overview', requireLogin, async (req, res) => {
    const userId = req.query.userId;
    if (!userId || userId !== req.session.userId) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [userId]);
        const user = userResult.rows[0];
        const completedQuestsResult = await pool.query('SELECT * FROM user_quests WHERE user_id = $1', [user.id]);
        const redeemableCodesResult = await pool.query('SELECT COUNT(*) FROM redeemable_codes WHERE user_id = $1 AND is_used = FALSE', [user.id]);

        res.json({
            totalEarnings: user.points || 0,
            questsCompleted: completedQuestsResult.rows,
            redeemableCodes: parseInt(redeemableCodesResult.rows[0].count, 10)
        });
    } catch (err) {
        console.error('Quest-overview error:', err);
        res.status(500).json({ error: 'Failed to fetch quest overview' });
    }
});

app.post('/withdraw', requireLogin, async (req, res) => {
    const { amount } = req.body;
    const userDbId = req.user.id; 
    const withdrawalAmount = parseFloat(amount);

    if (isNaN(withdrawalAmount) || withdrawalAmount <= 0) {
        return res.status(400).json({ error: 'Invalid withdrawal amount.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const userResult = await client.query('SELECT points FROM users WHERE id = $1 FOR UPDATE', [userDbId]);
        const user = userResult.rows[0];

        if (!user || user.points < withdrawalAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Insufficient balance.' });
        }

        await client.query('UPDATE users SET points = points - $1 WHERE id = $2', [withdrawalAmount, userDbId]);

        const code = crypto.randomBytes(8).toString('hex').toUpperCase();
        await client.query(
            'INSERT INTO redeemable_codes (user_id, code, amount) VALUES ($1, $2, $3)',
            [userDbId, code, withdrawalAmount]
        );

        await client.query('COMMIT');
        res.json({ message: 'Withdrawal successful!', code });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Withdrawal error:', err);
        res.status(500).json({ error: 'Failed to process withdrawal.' });
    } finally {
        client.release();
    }
});

app.get('/redeemable-codes', requireLogin, async (req, res) => {
    const userId = req.query.userId;
     if (!userId || userId !== req.session.userId) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }
    try {
        const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [userId]);
        if (userResult.rows.length === 0) return res.status(404).json({error: "User not found"});
        const userDbId = userResult.rows[0].id;
        
        const codesResult = await pool.query('SELECT code, amount, created_at FROM redeemable_codes WHERE user_id = $1 AND is_used = FALSE ORDER BY created_at DESC', [userDbId]);
        res.json({ codes: codesResult.rows });
    } catch (err) {
        console.error('Error fetching redeemable codes:', err);
        res.status(500).json({ error: 'Failed to fetch redeemable codes.' });
    }
});


app.get('/quests', requireLogin, async (req, res) => {
    try {
        const questsResult = await pool.query('SELECT * FROM quests ORDER BY id ASC');
        res.json({ quests: questsResult.rows });
    } catch (err) {
        console.error('Error reading quests:', err);
        res.json({ quests: [] });
    }
});

app.post('/quests', requireAdmin, async (req, res) => {
    res.status(501).json({ message: "Admin quest management not yet implemented with database." });
});

app.get('/quests/:questId/questions', requireLogin, async (req, res) => {
    const { questId } = req.params;
    try {
        const result = await pool.query('SELECT * FROM quest_questions WHERE quest_id = $1 ORDER BY id ASC', [questId]);
        res.json({ questions: result.rows });
    } catch (err) {
        console.error('Error fetching questions:', err);
        res.status(500).json({ error: 'Failed to fetch questions' });
    }
});

app.post('/quests/:questId/questions', requireAdmin, async (req, res) => {
    res.status(501).json({ message: "Admin question management not yet implemented with database." });
});

app.delete('/quests/:questId/questions/:questionId', requireAdmin, async (req, res) => {
    res.status(501).json({ message: "Admin question management not yet implemented with database." });
});

// === UPDATED /submit-quiz ENDPOINT (SURVEY LOGIC) ===
app.post('/submit-quiz/:questId', requireLogin, async (req, res) => {
    const questId = parseInt(req.params.questId, 10);
    const userDbId = req.user.id;
    const { answers } = req.body;

    if (!Array.isArray(answers)) {
        return res.status(400).json({ error: 'Invalid answers format.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Check if quest is already completed
        const existingCompletion = await client.query(
            'SELECT 1 FROM user_quests WHERE user_id = $1 AND quest_id = $2',
            [userDbId, questId]
        );
        if (existingCompletion.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'You have already completed this quest.' });
        }

        // 2. Fetch quest and its questions
        const questResult = await client.query('SELECT * FROM quests WHERE id = $1', [questId]);
        const quest = questResult.rows[0];
        if (!quest) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Quest not found.' });
        }

        const questionsResult = await client.query(
            'SELECT id FROM quest_questions WHERE quest_id = $1',
            [questId]
        );
        const questions = questionsResult.rows;

        // 3. Check for completion (survey-style) - ensure every question has a non-empty answer
        const allAnswered = answers.length === questions.length && answers.every(ans => ans !== undefined && ans !== null && ans !== '');
        
        if (allAnswered) {
            // 4. Award points and mark as complete (Success)
            const rewardValue = parsePayout(quest.reward);
            await client.query('UPDATE users SET points = points + $1 WHERE id = $2', [rewardValue, userDbId]);
            await client.query(
                'INSERT INTO user_quests (user_id, quest_id, completed_at) VALUES ($1, $2, NOW())',
                [userDbId, questId]
            );
            await client.query('COMMIT');

            const referralLink = `${process.env.BASE_URL || `http://localhost:${PORT}`}/referral?questId=${questId}&referrerId=${encodeURIComponent(req.user.username)}`;
            
            res.json({
                success: true,
                message: "Quest completed successfully!",
                reward: quest.reward,
                referralLink
            });

        } else {
            // User did not answer all questions
            await client.query('ROLLBACK');
            res.json({
                success: false,
                message: "Please answer all questions to complete the quest."
            });
        }

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error submitting quiz:', err);
        res.status(500).json({ error: 'An error occurred while submitting the quest.' });
    } finally {
        client.release();
    }
});


app.get('/quests/:questId/responses', requireAdmin, async (req, res) => {
    res.json({});
});

app.get('/referrals', requireLogin, async (req, res) => {
     const userId = req.query.userId;
     if (!userId || userId !== req.session.userId) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }
    res.json({});
});

app.get('/generate-referral-link', requireLogin, async (req, res) => {
    const { questId } = req.query;
    const userId = req.user.username;
    if (!questId || !userId) {
        return res.status(400).json({ error: 'Invalid quest or user ID' });
    }
    const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
    const referralLink = `${baseUrl}/referral?questId=${questId}&referrerId=${encodeURIComponent(userId)}`;
    res.json({ referralLink });
});

app.get('/referral', async (req, res) => {
    const questId = parseInt(req.query.questId);
    const referrerId = req.query.referrerId;
    try {
        const questResult = await pool.query('SELECT * FROM quests WHERE id = $1', [questId]);
        const quest = questResult.rows[0];
        if (!quest || !quest.quiz_page) return res.status(404).json({ error: 'Quest not found' });
        res.redirect(quest.quiz_page);
    } catch (err) {
        console.error('Referral error:', err);
        res.status(500).json({ error: 'Failed to process referral' });
    }
});

app.get('/experts', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM professionals WHERE type = 'expert'");
        const expertsObject = result.rows.reduce((obj, item) => {
            obj[item.id] = item;
            return obj;
        }, {});
        res.json(expertsObject);
    } catch (err) {
        console.error('Error reading experts:', err);
        res.status(500).json({});
    }
});

app.post('/experts', requireAdmin, async (req, res) => {
    res.status(501).json({ message: "Admin expert management not yet implemented with database." });
});

app.get('/expert/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query("SELECT * FROM professionals WHERE id = $1 AND type = 'expert'", [id]);
        const expert = result.rows[0];
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
        await pool.query('INSERT INTO bookings (user_id, professional_id, reason, preferred_date) VALUES ($1, $2, $3, $4)', [req.user.id, expertId, reason, preferredDate]);
        res.json({ success: true, message: 'Booking submitted' });
    } catch (err) {
        console.error('Booking error:', err);
        res.status(500).json({ error: 'Failed to submit booking' });
    }
});

app.get('/affiliate-programs', requireLogin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM affiliate_programs ORDER BY id');
        res.json({ programs: result.rows });
    } catch (err) {
        console.error('Error fetching affiliate programs:', err);
        res.status(500).json({ programs: [] });
    }
});

app.get('/track', async (req, res) => {
    const { programId, affiliate_id } = req.query;
    if (!programId || !affiliate_id) {
        return res.status(400).send('<h1>Missing tracking information.</h1>');
    }
    try {
        const programResult = await pool.query('SELECT destination_url FROM affiliate_programs WHERE id = $1', [programId]);
        const program = programResult.rows[0];
        
        if (!program || !program.destination_url) {
            return res.status(404).send('<h1>Affiliate Program Not Found</h1>');
        }
        await pool.query('INSERT INTO affiliate_clicks (program_id, affiliate_username, ip_address) VALUES ($1, $2, $3)', [programId, affiliate_id, req.ip]);
        res.redirect(program.destination_url);
    } catch (err) {
        console.error('Affiliate tracking error:', err);
        res.status(500).send('<h1>Error processing affiliate link.</h1>');
    }
});

app.post('/api/affiliate/conversion', async (req, res) => {
    const { programId, affiliateId, conversionValue } = req.body;
    if (!programId || !affiliateId) {
        return res.status(400).json({ error: 'Missing conversion information.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const programResult = await client.query('SELECT * FROM affiliate_programs WHERE id = $1', [programId]);
        const program = programResult.rows[0];
        if (!program) {
             await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Program not found.' });
        }
        const userResult = await client.query('SELECT id FROM users WHERE username = $1', [affiliateId]);
        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({error: 'Affiliate user not found'});
        }
        const affiliateDbId = userResult.rows[0].id;
        const payoutAmount = parsePayout(program.payout); 
        await client.query(
            'INSERT INTO conversions (program_id, affiliate_username, conversion_value, payout_amount) VALUES ($1, $2, $3, $4)',
            [programId, affiliateId, conversionValue || 0, payoutAmount]
        );
        await client.query('UPDATE users SET points = points + $1 WHERE id = $2', [payoutAmount, affiliateDbId]);
        await client.query('COMMIT');
        res.status(201).json({ message: 'Conversion recorded successfully.' });
    } catch(err) {
        await client.query('ROLLBACK');
        console.error('Conversion recording error:', err);
        res.status(500).json({error: 'Failed to record conversion.'});
    } finally {
        client.release();
    }
});

app.get('/api/affiliate/stats', requireLogin, async (req, res) => {
    const affiliateId = req.user.username;
    try {
        const clicksResult = await pool.query('SELECT COUNT(*) FROM affiliate_clicks WHERE affiliate_username = $1', [affiliateId]);
        const conversionsResult = await pool.query('SELECT COUNT(*), SUM(payout_amount) as earnings FROM conversions WHERE affiliate_username = $1', [affiliateId]);
        res.json({
            totalClicks: parseInt(clicksResult.rows[0].count, 10),
            totalConversions: parseInt(conversionsResult.rows[0].count, 10),
            totalEarnings: parseFloat(conversionsResult.rows[0].earnings) || 0,
        });
    } catch(err) {
        console.error("Error fetching affiliate stats:", err);
        res.status(500).json({error: 'Could not fetch stats.'});
    }
});

app.get('/api/affiliate/history', requireLogin, async (req, res) => {
    res.json([]);
});

app.get('/education-content', async (req, res) => {
    try {
        const categoriesResult = await pool.query('SELECT * FROM education_categories ORDER BY id');
        const contentResult = await pool.query('SELECT * FROM education_content');
        
        const categories = categoriesResult.rows.map(cat => ({
            name: cat.name,
            content: contentResult.rows.filter(con => con.category_id === cat.id)
        }));
        res.json({ categories });
    } catch (err) {
        console.error('Error fetching education content:', err);
        res.status(500).json({ categories: [] });
    }
});

app.get('/products', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM products ORDER BY id');
        res.json({ products: result.rows });
    } catch (err) {
        console.error('Error reading products:', err);
        res.status(500).json({products:[]});
    }
});

app.get('/groweasy.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'groweasy.html')));
app.get('/affiliate.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'affiliate.html')));
app.get('/education.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'education.html')));
app.get('/founder.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'founder.html')));
app.get('/admin-experts.html', requireAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-experts.html'))); 

app.post('/block-user', requireAdmin, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    try {
        const result = await pool.query('UPDATE users SET blocked = true WHERE username = $1 RETURNING *', [username]);
        if(result.rowCount === 0) return res.status(404).json({error: 'User not found'});
        res.json({ message: `User ${username} blocked` });
    } catch(err) {
        console.error("Error blocking user:", err);
        res.status(500).json({error: 'Failed to block user'});
    }
});

app.post('/delete-user', requireAdmin, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
     try {
        const result = await pool.query('DELETE FROM users WHERE username = $1 RETURNING *', [username]);
        if(result.rowCount === 0) return res.status(404).json({error: 'User not found'});
        res.json({ message: `User ${username} deleted` });
    } catch(err) {
        console.error("Error deleting user:", err);
        res.status(500).json({error: 'Failed to delete user'});
    }
});

app.get('/total-users', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT COUNT(*) FROM users');
        res.json({ totalUsers: parseInt(result.rows[0].count) });
    } catch(err) {
         console.error("Error fetching total users:", err);
         res.status(500).json({error: 'Could not fetch user count'});
    }
});

app.get('/online-users', requireAdmin, (req, res) => {
    res.json({ onlineUsers: Math.floor(Math.random() * 10) + 1 });
});

app.get('/founders', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM professionals WHERE type = 'founder'");
        const foundersObject = result.rows.reduce((obj, item) => {
            obj[item.id] = item;
            return obj;
        }, {});
        res.json(foundersObject);
    } catch (err) {
        console.error('Error reading founders:', err);
        res.status(500).json({});
    }
});

app.get('/founder/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query("SELECT * FROM professionals WHERE id = $1 AND type = 'founder'", [id]);
        const founder = result.rows[0];
        if (!founder) return res.status(404).json({ error: 'Expert not found' });
        res.json(founder);
    } catch (err) {
        console.error('Error fetching founder:', err);
        res.status(500).json({ error: 'Failed to fetch founder' });
    }
});

app.post('/book-founder', requireLogin, async (req, res) => {
    const { founderId, reason, preferredDate } = req.body;
    if (!founderId || !reason || !preferredDate) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        await pool.query('INSERT INTO bookings (user_id, professional_id, reason, preferred_date) VALUES ($1, $2, $3, $4)', [req.user.id, founderId, reason, preferredDate]);
        res.json({ success: true, message: 'Booking submitted' });
    } catch (err) {
        console.error('Booking error:', err);
        res.status(500).json({ error: 'Failed to submit booking' });
    }
});

app.post('/founders', requireAdmin, async (req, res) => {
    res.status(501).json({ message: "Admin founder management not yet implemented with database." });
});

// NEW: Endpoint for Growth Settings
app.post('/api/users/:userId/settings', requireLogin, async (req, res) => {
    const { userId } = req.params;
    const { settings } = req.body;

    if (userId !== req.session.userId) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    console.log(`Received settings for user ${userId}:`, settings);
    
    res.json({ success: true, message: 'Settings saved successfully (simulated)!' });
});


app.use((req, res, next) => {
    if (req.session && req.session.userId) {
        req.session.lastActivity = Date.now();
    }
    next();
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}. Connected to database.`);
require('dotenv').config();

const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
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

// --- Hardcoded Admin Credentials for testing ---
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'kingslayer';
const saltRounds = 10;

// --- Hashed Admin Password ---
let ADMIN_PASSWORD_HASH;
(async () => {
    if (ADMIN_PASSWORD) {
        ADMIN_PASSWORD_HASH = await bcrypt.hash(ADMIN_PASSWORD, saltRounds);
        console.log("Admin password hashed successfully.");
    } else {
        console.error("ADMIN_PASSWORD is not set!");
    }
})();


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

// --- Multer setup for file uploads ---
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, 'public/uploads');
    // Synchronously create the directory if it doesn't exist to prevent race conditions.
    if (!fsSync.existsSync(uploadPath)) {
        fsSync.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    // Generate a unique filename to prevent overwrites.
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// Create a base multer instance
const upload = multer({ storage: storage });

// Middleware for handling quest-related uploads (multiple fields)
const questUpload = upload.fields([
    { name: 'questBackground', maxCount: 1 },
    { name: 'questBanner', maxCount: 1 }
]);


// Middleware functions (requireLogin, requireAdmin, etc.)
const requireLogin = async (req, res, next) => {
    if (!req.session.userId) {
        if (req.headers.accept && req.headers.accept.includes('text/html')) {
            return res.redirect('/auth.html');
        }
        return res.status(401).json({ error: 'Unauthorized, please log in' });
    }
    if (req.session.isAdmin) {
        if (req.session.userId === ADMIN_USERNAME) {
            req.user = { id: 'admin', username: 'admin' }; // Create a mock admin user object
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
    if (req.session.userId && req.session.isAdmin && req.session.userId === ADMIN_USERNAME) {
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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- UPDATED FINANCIAL ADMIN API ENDPOINTS ---
app.get('/api/admin/financial-summary', requireAdmin, async (req, res) => {
    try {
        const transactionsQuery = `
            (SELECT u.username, 'Quest Reward: ' || q.title AS description, public.parse_payout(q.reward) AS amount, 'credit' as type, uq.completed_at AS date FROM user_quests uq JOIN users u ON uq.user_id = u.id JOIN quests q ON uq.quest_id = q.id)
            UNION ALL
            (SELECT u.username, 'Job Payment: ' || ap.title AS description, je.amount, 'credit' AS type, je.created_at AS date
             FROM job_earnings je
             JOIN users u ON je.user_id = u.id
             JOIN affiliate_programs ap ON je.program_id = ap.id)
            UNION ALL
            (SELECT u.username, 'Withdrawal' AS description, w.amount, 'debit' as type, w.created_at AS date FROM withdrawals w JOIN users u ON w.user_id = u.id WHERE w.status = 'approved')
            ORDER BY date DESC;
        `;
        
        const payoutsQuery = `
            SELECT w.id, u.username, w.amount, w.wallet_address, w.chain, w.status, w.created_at
            FROM withdrawals w
            JOIN users u ON w.user_id = u.id
            WHERE w.status = 'pending'
            ORDER BY w.created_at ASC;
        `;

        const [transactionsResult, payoutsResult] = await Promise.all([
            pool.query(transactionsQuery),
            pool.query(payoutsQuery)
        ]);

        res.json({
            transactions: transactionsResult.rows,
            payouts: payoutsResult.rows
        });

    } catch (err) {
        console.error('Error fetching financial summary:', err);
        res.status(500).json({ error: 'Failed to fetch financial data' });
    }
});

app.post('/api/admin/withdrawals/approve', requireAdmin, async (req, res) => {
    const { withdrawalId, transactionHash } = req.body;
    if (!withdrawalId || !transactionHash) {
        return res.status(400).json({ error: 'Withdrawal ID and Transaction Hash are required.' });
    }
    try {
        const result = await pool.query(
            "UPDATE withdrawals SET status = 'approved', transaction_hash = $1 WHERE id = $2 AND status = 'pending' RETURNING *",
            [transactionHash, withdrawalId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Withdrawal not found or already processed.' });
        }
        res.json({ success: true, message: 'Withdrawal approved and transaction hash stored.' });
    } catch (err) {
        console.error('Error approving withdrawal:', err);
        res.status(500).json({ error: 'Failed to approve withdrawal.' });
    }
});

app.post('/api/admin/withdrawals/reject', requireAdmin, async (req, res) => {
    const { withdrawalId } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const withdrawalResult = await client.query("SELECT user_id, amount FROM withdrawals WHERE id = $1 AND status = 'pending' FOR UPDATE", [withdrawalId]);
        if (withdrawalResult.rows.length === 0) {
            throw new Error('Withdrawal not found or already processed.');
        }
        const withdrawal = withdrawalResult.rows[0];

        await client.query('UPDATE users SET points = points + $1 WHERE id = $2', [withdrawal.amount, withdrawal.user_id]);
        await client.query("UPDATE withdrawals SET status = 'rejected' WHERE id = $1", [withdrawalId]);

        await client.query('COMMIT');
        res.json({ success: true, message: 'Withdrawal rejected and funds returned to user.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error rejecting withdrawal:', err);
        res.status(500).json({ error: 'Failed to reject withdrawal.' });
    } finally {
        client.release();
    }
});


// --- UPDATED DASHBOARD API ENDPOINT ---
app.get('/api/dashboard-stats', requireAdmin, async (req, res) => {
    try {
        const queries = {
            totalUsers: pool.query('SELECT COUNT(*) FROM users'),
            questParticipants: pool.query('SELECT COUNT(DISTINCT user_id) FROM user_quests'),
            jobApplicants: pool.query('SELECT COUNT(DISTINCT user_id) FROM user_jobs'),
            learnParticipants: pool.query('SELECT COUNT(DISTINCT user_id) FROM user_material_progress'),
            buildParticipants: pool.query('SELECT COUNT(DISTINCT user_id) FROM bookings'),
            jobEarnings: pool.query(`SELECT SUM(amount) as total FROM job_earnings`),
            questEarnings: pool.query(`SELECT SUM(public.parse_payout(q.reward)) as total FROM user_quests uq JOIN quests q ON uq.quest_id = q.id`),
            totalWithdrawn: pool.query(`SELECT SUM(amount) as total FROM withdrawals WHERE status = 'approved'`),
            userRegistrationGrowth: pool.query(`SELECT date_trunc('month', created_at) as month, COUNT(*) as count FROM users WHERE created_at IS NOT NULL GROUP BY 1 ORDER BY 1`),
            questCompletions: pool.query(`SELECT COUNT(*) FROM user_quests`),
            totalQuests: pool.query(`SELECT COUNT(*) FROM quests`)
        };

        const results = await Promise.allSettled(Object.values(queries));
        
        const [
            totalUsersResult,
            questParticipantsResult,
            jobApplicantsResult,
            learnParticipantsResult,
            buildParticipantsResult,
            jobEarningsResult,
            questEarningsResult,
            totalWithdrawnResult,
            userRegistrationGrowthResult,
            questCompletionsResult,
            totalQuestsResult
        ] = results;

        const getFulfilledValue = (result, path) => {
            if (result.status === 'fulfilled') {
                let value = result.value.rows;
                if (path) {
                    const keys = path.split('.');
                    for(const key of keys) {
                        if (value === undefined || value === null) return null;
                        value = value[key];
                    }
                }
                return value;
            }
            return null;
        };
        
        const userRegData = getFulfilledValue(userRegistrationGrowthResult);
        const questCompletionsData = getFulfilledValue(questCompletionsResult, '0.count');
        const totalQuestsData = getFulfilledValue(totalQuestsResult, '0.count');

        res.json({
            keyMetrics: {
                totalUsers: { status: totalUsersResult.status, value: getFulfilledValue(totalUsersResult, '0.count') },
                questParticipants: { status: questParticipantsResult.status, value: getFulfilledValue(questParticipantsResult, '0.count') },
                jobApplicants: { status: jobApplicantsResult.status, value: getFulfilledValue(jobApplicantsResult, '0.count') },
                learnParticipants: { status: learnParticipantsResult.status, value: getFulfilledValue(learnParticipantsResult, '0.count') },
                buildParticipants: { status: buildParticipantsResult.status, value: getFulfilledValue(buildParticipantsResult, '0.count') },
                jobEarnings: { status: jobEarningsResult.status, value: getFulfilledValue(jobEarningsResult, '0.total') },
                questEarnings: { status: questEarningsResult.status, value: getFulfilledValue(questEarningsResult, '0.total') },
                totalWithdrawn: { status: totalWithdrawnResult.status, value: getFulfilledValue(totalWithdrawnResult, '0.total') },
            },
            charts: {
                userRegistration: {
                    status: userRegistrationGrowthResult.status,
                    labels: userRegData ? userRegData.map(r => new Date(r.month).toLocaleString('default', { month: 'short' })) : [],
                    data: userRegData ? userRegData.map(r => r.count) : []
                },
                questCompletion: {
                    status: questCompletionsResult.status === 'fulfilled' && totalQuestsResult.status === 'fulfilled' ? 'fulfilled' : 'rejected',
                    labels: ['Completed', 'Not Completed'],
                    data: [questCompletionsData, totalQuestsData - questCompletionsData]
                }
            }
        });

    } catch (err) {
        console.error('Error in dashboard stats endpoint:', err);
        res.status(500).json({ error: 'A critical error occurred on the server.' });
    }
});

// --- UPDATED USERS PAGE API ENDPOINT ---
app.get('/api/users-data', requireAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                u.id,
                u.username,
                u.full_name,
                u.email,
                u.avatar,
                u.points,
                u.blocked,
                u.created_at,
                (SELECT r_by.username FROM users r_by JOIN referrals r ON r_by.id = r.referrer_id WHERE r.referred_id = u.id LIMIT 1) AS referred_by,
                COALESCE((SELECT COUNT(*) FROM referrals WHERE referrer_id = u.id AND type = 'platform'), 0) AS total_app_referrals,
                COALESCE((SELECT COUNT(*) FROM referrals WHERE referrer_id = u.id AND type = 'quest'), 0) AS total_quest_referrals,
                COALESCE(uq.quest_count, 0) AS quests_joined,
                COALESCE(uj_ip.in_progress_count, 0) AS jobs_in_progress,
                COALESCE(jc.completed_count, 0) AS jobs_done,
                COALESCE(w.total_withdrawn, 0) AS total_withdrawn
            FROM users u
            LEFT JOIN (SELECT user_id, COUNT(*) as quest_count FROM user_quests GROUP BY user_id) uq ON u.id = uq.user_id
            LEFT JOIN (SELECT user_id, COUNT(*) as in_progress_count FROM user_jobs GROUP BY user_id) uj_ip ON u.id = uj_ip.user_id
            LEFT JOIN (SELECT user_id, COUNT(*) as completed_count FROM job_completions GROUP BY user_id) jc ON u.id = jc.user_id
            LEFT JOIN (SELECT user_id, SUM(amount) as total_withdrawn FROM withdrawals WHERE status = 'approved' GROUP BY user_id) w ON u.id = w.user_id
            ORDER BY u.created_at DESC;
        `;

        const usersResult = await pool.query(query);
        
        const usersWithStats = usersResult.rows.map(user => {
            const balance = parseFloat(user.points) || 0;
            const totalWithdrawn = parseFloat(user.total_withdrawn) || 0;
            const totalEarnings = balance + totalWithdrawn;

            return {
                id: user.id,
                name: user.full_name || user.username,
                username: user.username,
                avatar: user.avatar || `https://placehold.co/40x40/E2E8F0/4A5568?text=${(user.full_name || user.username).charAt(0).toUpperCase()}`,
                email: user.email,
                registeredDate: new Date(user.created_at).toLocaleDateString(),
                status: user.blocked ? 'Banned' : 'Active',
                referredBy: user.referred_by,
                totalAppReferrals: parseInt(user.total_app_referrals, 10),
                totalQuestReferrals: parseInt(user.total_quest_referrals, 10),
                questsJoined: parseInt(user.quests_joined, 10),
                jobsInProgress: parseInt(user.jobs_in_progress, 10),
                jobsDone: parseInt(user.jobs_done, 10),
                totalEarnings: totalEarnings.toFixed(2),
                balance: balance.toFixed(2)
            };
        });

        res.json({ users: usersWithStats });

    } catch (err) {
        console.error('Error fetching users data:', err);
        res.status(500).json({ error: 'Failed to fetch users data' });
    }
});

// --- QUESTS PAGE API ENDPOINT ---
app.get('/api/quests-data', requireAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                q.*,
                COALESCE(uq.participants_count, 0) AS participants_count
            FROM 
                quests q
            LEFT JOIN (
                SELECT 
                    quest_id, 
                    COUNT(DISTINCT user_id) as participants_count 
                FROM 
                    user_quests 
                GROUP BY 
                    quest_id
            ) uq ON q.id = uq.quest_id
            ORDER BY 
                q.id ASC;
        `;

        const questsResult = await pool.query(query);
        
        res.json({ quests: questsResult.rows });

    } catch (err) {
        console.error('Error fetching quests data:', err);
        res.status(500).json({ error: 'Failed to fetch quests data' });
    }
});

// --- BUILD PAGE API ENDPOINT ---
app.get('/api/build-data', requireLogin, async (req, res) => {
    try {
        const [expertsResult, productsResult, tabsResult, contentResult, expertMapResult] = await Promise.all([
            pool.query('SELECT * FROM experts'),
            pool.query('SELECT * FROM products'),
            pool.query('SELECT * FROM product_tabs'),
            pool.query('SELECT * FROM tab_content'),
            pool.query('SELECT * FROM product_expert_map')
        ]);

        const expertsData = expertsResult.rows.reduce((acc, expert) => {
            acc[expert.id] = expert;
            return acc;
        }, {});

        const buildProductsData = productsResult.rows.reduce((acc, product) => {
            const productTabs = tabsResult.rows.filter(t => t.product_id === product.id);
            const tabsData = productTabs.reduce((tabAcc, tab) => {
                if (tab.tab_key === 'experts') {
                    tabAcc[tab.tab_key] = {
                        title: tab.title,
                        icon: tab.icon,
                        expertIds: expertMapResult.rows
                            .filter(map => map.product_id === product.id)
                            .map(map => map.expert_id.toString())
                    };
                } else {
                    tabAcc[tab.tab_key] = {
                        title: tab.title,
                        icon: tab.icon,
                        content: contentResult.rows
                            .filter(c => c.tab_id === tab.id)
                            .map(c => ({ title: c.title, content: c.content, link: c.link }))
                    };
                }
                return tabAcc;
            }, {});

            acc[product.id] = {
                title: product.title,
                icon: product.icon,
                color: product.color,
                description: product.description,
                guideTitle: product.guide_title,
                guideDescription: product.guide_description,
                tabs: tabsData
            };
            return acc;
        }, {});

        res.json({
            expertsData,
            buildProductsData
        });

    } catch (err) {
        console.error('Error fetching build data from DB:', err);
        res.status(500).json({ error: 'Failed to fetch build data' });
    }
});

// --- EDUCATION PAGE API ENDPOINTS ---
app.get('/api/education/content', requireLogin, async (req, res) => {
    try {
        const [skillsResult, materialsResult, expertsResult, skillExpertMapResult] = await Promise.all([
            pool.query('SELECT * FROM education_skills ORDER BY title'),
            pool.query('SELECT * FROM education_materials ORDER BY id'),
            pool.query('SELECT * FROM education_experts ORDER BY name'),
            pool.query('SELECT * FROM skill_expert_map')
        ]);

        const learningData = skillsResult.rows.reduce((acc, skill) => {
            acc[skill.id] = {
                ...skill,
                materials: materialsResult.rows.filter(m => m.skill_id === skill.id),
                expertIds: skillExpertMapResult.rows
                    .filter(map => map.skill_id === skill.id)
                    .map(map => map.expert_id)
            };
            return acc;
        }, {});

        const expertsData = expertsResult.rows.reduce((acc, expert) => {
            acc[expert.id] = expert;
            return acc;
        }, {});

        res.json({ learningData, expertsData });
    } catch (err) {
        console.error('Error fetching education content from DB:', err);
        res.status(500).json({ error: 'Failed to fetch education content' });
    }
});

app.get('/api/education/user-data/:skillId', requireLogin, async (req, res) => {
    const { skillId } = req.params;
    const userId = req.user.id;

    try {
        const [progressResult, planResult] = await Promise.all([
            pool.query('SELECT material_id FROM user_material_progress WHERE user_id = $1', [userId]),
            pool.query('SELECT * FROM study_plans WHERE user_id = $1 AND skill_id = $2 AND is_active = TRUE', [userId, skillId])
        ]);

        const completedMaterials = progressResult.rows.map(r => r.material_id);
        const activePlan = planResult.rows[0] || null;

        if (activePlan) {
            const daysResult = await pool.query('SELECT day_of_week FROM study_plan_days WHERE study_plan_id = $1', [activePlan.id]);
            activePlan.days = daysResult.rows.map(r => r.day_of_week);
        }

        res.json({ completedMaterials, activePlan });
    } catch (err) {
        console.error(`Error fetching user data for skill ${skillId}:`, err);
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});

app.post('/api/education/progress', requireLogin, async (req, res) => {
    const { materialId, completed } = req.body;
    const userId = req.user.id;

    try {
        if (completed) {
            await pool.query('INSERT INTO user_material_progress (user_id, material_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [userId, materialId]);
        } else {
            await pool.query('DELETE FROM user_material_progress WHERE user_id = $1 AND material_id = $2', [userId, materialId]);
        }
        res.json({ success: true });
    } catch (err) {
        console.error('Error updating progress:', err);
        res.status(500).json({ error: 'Failed to update progress' });
    }
});

app.post('/api/education/study-plan', requireLogin, async (req, res) => {
    const { skillId, goal, days, time } = req.body;
    const userId = req.user.id;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('UPDATE study_plans SET is_active = FALSE WHERE user_id = $1 AND skill_id = $2', [userId, skillId]);

        const planResult = await client.query(
            'INSERT INTO study_plans (user_id, skill_id, goal, reminder_time) VALUES ($1, $2, $3, $4) RETURNING id',
            [userId, skillId, goal, time]
        );
        const planId = planResult.rows[0].id;

        if (days && days.length > 0) {
            const dayValues = days.map(day => `(${planId}, ${day})`).join(',');
            await client.query(`INSERT INTO study_plan_days (study_plan_id, day_of_week) VALUES ${dayValues}`);
        }
        
        await client.query('COMMIT');
        res.status(201).json({ success: true, message: 'Study plan created!' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error creating study plan:', err);
        res.status(500).json({ error: 'Failed to create study plan' });
    } finally {
        client.release();
    }
});

// --- Group Study API Endpoints ---

// Invite a user to a study group
app.post('/api/education/study-group/invite', requireLogin, async (req, res) => {
    const { skillId, inviteeEmail } = req.body;
    const inviterId = req.user.id;

    if (!inviterId) {
        return res.status(401).json({ message: 'You must be logged in to invite users.' });
    }

    try {
        // Find the user being invited
        const inviteeResult = await pool.query('SELECT id FROM users WHERE email = $1', [inviteeEmail]);
        if (inviteeResult.rows.length === 0) {
            return res.status(404).json({ message: 'User with that email does not exist.' });
        }
        const inviteeId = inviteeResult.rows[0].id;

        if (inviteeId === inviterId) {
            return res.status(400).json({ message: 'You cannot invite yourself.' });
        }

        // Find or create the study group
        let groupResult = await pool.query('SELECT id FROM study_groups WHERE skill_id = $1 AND creator_id = $2', [skillId, inviterId]);
        let groupId;

        if (groupResult.rows.length === 0) {
            // Create a new group if one doesn't exist
            const newGroupResult = await pool.query(
                'INSERT INTO study_groups (skill_id, creator_id) VALUES ($1, $2) RETURNING id',
                [skillId, inviterId]
            );
            groupId = newGroupResult.rows[0].id;
            // The creator is automatically a member
            await pool.query(
                'INSERT INTO study_group_invitations (study_group_id, inviter_id, invitee_id, status) VALUES ($1, $2, $3, $4)',
                [groupId, inviterId, inviterId, 'accepted']
            );
        } else {
            groupId = groupResult.rows[0].id;
        }

        // Create the invitation
        const invitationResult = await pool.query(
            'INSERT INTO study_group_invitations (study_group_id, inviter_id, invitee_id) VALUES ($1, $2, $3) ON CONFLICT (study_group_id, invitee_id) DO NOTHING RETURNING *',
            [groupId, inviterId, inviteeId]
        );

        if (invitationResult.rows.length === 0) {
             return res.status(409).json({ message: 'This user has already been invited.' });
        }

        res.status(201).json({ success: true, invitation: invitationResult.rows[0] });

    } catch (error) {
        console.error('Error sending invitation:', error);
        res.status(500).json({ message: 'Server error while sending invitation.' });
    }
});

// Get data for a specific study group
app.get('/api/education/study-group/:skillId', requireLogin, async (req, res) => {
    const { skillId } = req.params;
    const userId = req.user.id;

    if (!userId) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    
    try {
        // Find the group the user is part of for this skill
        const groupMembership = await pool.query(`
            SELECT sg.id FROM study_groups sg
            JOIN study_group_invitations sgi ON sg.id = sgi.study_group_id
            WHERE sgi.invitee_id = $1 AND sg.skill_id = $2 AND sgi.status = 'accepted'
        `, [userId, skillId]);

        if (groupMembership.rows.length === 0) {
            // If the user isn't an accepted member, check if they are the creator of a group for this skill
             const creatorGroup = await pool.query('SELECT id FROM study_groups WHERE creator_id = $1 AND skill_id = $2', [userId, skillId]);
             if (creatorGroup.rows.length === 0) {
                // If they are not in a group and not a creator, return empty data
                return res.json({ members: [], invitations: [] }); 
             }
             groupMembership.rows.push(creatorGroup.rows[0]);
        }
        const groupId = groupMembership.rows[0].id;

        // Get all accepted members and their progress using a more robust LEFT JOIN
        const membersResult = await pool.query(`
            SELECT
                u.id,
                u.username AS name,
                u.avatar,
                COUNT(ump.material_id) AS completed_count
            FROM users u
            JOIN study_group_invitations sgi ON u.id = sgi.invitee_id
            LEFT JOIN (
                SELECT ump_inner.user_id, ump_inner.material_id
                FROM user_material_progress ump_inner
                JOIN education_materials em ON ump_inner.material_id = em.id
                WHERE em.skill_id = $2
            ) AS ump ON ump.user_id = u.id
            WHERE sgi.study_group_id = $1 AND sgi.status = 'accepted'
            GROUP BY u.id, u.username, u.avatar
        `, [groupId, skillId]);

        // Get total materials for progress calculation
        const materialsResult = await pool.query('SELECT COUNT(*) as total FROM education_materials WHERE skill_id = $1', [skillId]);
        const totalMaterials = parseInt(materialsResult.rows[0].total, 10);

        const members = membersResult.rows.map(m => ({
            ...m,
            progress: totalMaterials > 0 ? Math.round((parseInt(m.completed_count, 10) / totalMaterials) * 100) : 0
        }));

        // Get all invitations for this group
        const invitationsResult = await pool.query(`
            SELECT i.id, u.email, i.status FROM study_group_invitations i
            JOIN users u ON i.invitee_id = u.id
            WHERE i.study_group_id = $1 AND i.invitee_id != i.inviter_id
        `, [groupId]);
        
        res.json({ members, invitations: invitationsResult.rows });

    } catch (error) {
        console.error('Error fetching group data:', error);
        res.status(500).json({ message: 'Server error while fetching group data.' });
    }
});

// Get all pending invitations for the logged-in user
app.get('/api/education/invitations', requireLogin, async (req, res) => {
    const userId = req.user.id;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const invitations = await pool.query(`
            SELECT i.id, s.skill_id, u.username as inviter_name
            FROM study_group_invitations i
            JOIN study_groups s ON i.study_group_id = s.id
            JOIN users u ON i.inviter_id = u.id
            WHERE i.invitee_id = $1 AND i.status = 'pending'
        `, [userId]);
        res.json(invitations.rows);
    } catch (error) {
        console.error('Error fetching invitations:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Respond to an invitation
app.post('/api/education/invitations/respond', requireLogin, async (req, res) => {
    const { invitationId, response } = req.body; // response should be 'accepted' or 'declined'
    const userId = req.user.id;
    if (!userId) return res.status(401).json({ message: 'Unauthorized' });

    if (response !== 'accepted' && response !== 'declined') {
        return res.status(400).json({ message: 'Invalid response.' });
    }

    try {
        const result = await pool.query(
            'UPDATE study_group_invitations SET status = $1 WHERE id = $2 AND invitee_id = $3 RETURNING *',
            [response, invitationId, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Invitation not found or you are not authorized to respond.' });
        }
        res.json({ success: true, invitation: result.rows[0] });
    } catch (error) {
        console.error('Error responding to invitation:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// --- END EDUCATION PAGE API ENDPOINTS ---


// --- JOBS API ENDPOINTS ---
app.get('/api/jobs', requireLogin, async (req, res) => {
    try {
        const userId = req.user.id;

        const query = `
            SELECT 
                ap.*,
                uj.status AS user_job_status,
                uj.onboarding_link,
                uj.tracking_link,
                COALESCE(uj.rejection_reason, '') as rejection_reason,
                (SELECT COUNT(*) FROM user_jobs WHERE program_id = ap.id) AS participants_count
            FROM affiliate_programs ap
            LEFT JOIN user_jobs uj ON ap.id = uj.program_id AND uj.user_id = $1
            WHERE ap.status = 'Active'
            ORDER BY ap.id;
        `;
        const programsResult = await pool.query(query, [userId]);

        const jobs = programsResult.rows.map(program => {
            const requirements = [];
            if (program.guidelines) requirements.push(program.guidelines);
            if (program.pros && program.pros.length > 0) requirements.push(...program.pros.map(p => `Pro: ${p}`));
            if (program.cons && program.cons.length > 0) requirements.push(...program.cons.map(c => `Con: ${c}`));

            const categorySlug = program.category.toLowerCase().replace(/\s+/g, '-');

            return {
                id: program.id,
                title: program.title,
                category: categorySlug,
                payment: parsePayout(program.payout),
                description: program.details,
                requirements: requirements,
                destinationUrl: program.destination_url,
                brandWebsite: program.brand_website,
                socialLinks: program.social_links,
                brandDashboardUrl: program.brand_dashboard_url,
                status: program.user_job_status, // This is the user-specific status from the JOIN
                onboardingLink: program.onboarding_link,
                trackingLink: program.tracking_link,
                rejectionReason: program.rejection_reason,
                max_participants: program.max_participants,
                participants_count: parseInt(program.participants_count, 10)
            };
        });
        
        res.json({ jobs });
    } catch (err) {
        console.error('Error fetching jobs:', err);
        res.status(500).json({ error: 'Failed to fetch jobs' });
    }
});

app.post('/api/jobs/:jobId/request-links', requireLogin, async (req, res) => {
    const { jobId } = req.params;
    const userId = req.user.id;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Lock the program row to prevent race conditions
        const programResult = await client.query('SELECT max_participants, status FROM affiliate_programs WHERE id = $1 FOR UPDATE', [jobId]);
        if (programResult.rows.length === 0) {
            throw new Error('Job not found.');
        }
        const program = programResult.rows[0];

        if (program.status !== 'Active') {
            throw new Error('This job is currently not active.');
        }

        const participantsResult = await client.query('SELECT COUNT(*) as current_participants FROM user_jobs WHERE program_id = $1', [jobId]);
        const currentParticipants = parseInt(participantsResult.rows[0].current_participants, 10);

        if (program.max_participants !== null && currentParticipants >= program.max_participants) {
            throw new Error('This job is full and no longer accepting new applicants.');
        }

        const query = `
            INSERT INTO user_jobs (user_id, program_id, status) 
            VALUES ($1, $2, 'pending_links') 
            ON CONFLICT (user_id, program_id) DO NOTHING
        `;
        await client.query(query, [userId, jobId]);
        
        await client.query('COMMIT');
        res.status(201).json({ success: true, message: 'Job request sent to admin.' });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error requesting job links:', err);
        res.status(500).json({ error: err.message || 'Failed to request job.' });
    } finally {
        client.release();
    }
});


app.post('/api/jobs/:jobId/claim', requireLogin, async (req, res) => {
    const { jobId } = req.params;
    const { claimAmount, is_final_claim, submissionLink } = req.body;
    const userId = req.user.id;

    const parsedAmount = parseFloat(claimAmount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ error: 'A valid claim amount is required.' });
    }

    try {
        let result;
        if (submissionLink) {
            result = await pool.query(
                `INSERT INTO user_jobs (user_id, program_id, status, submission_link, current_claim_amount, is_final_claim, updated_at) 
                 VALUES ($1, $2, 'pending_review', $3, $4, $5, NOW())
                 ON CONFLICT (user_id, program_id) 
                 DO UPDATE SET 
                     status = 'pending_review', 
                     submission_link = $3, 
                     rejection_reason = NULL, 
                     current_claim_amount = $4,
                     is_final_claim = $5,
                     updated_at = NOW()
                 RETURNING *`,
                [userId, jobId, submissionLink, parsedAmount, is_final_claim]
            );
        } else {
            result = await pool.query(
                `UPDATE user_jobs 
                 SET status = 'reward_pending', current_claim_amount = $1, is_final_claim = $2, updated_at = NOW() 
                 WHERE user_id = $3 AND program_id = $4 AND status = 'active' 
                 RETURNING *`,
                [parsedAmount, is_final_claim, userId, jobId]
            );
        }

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Active job not found for this user or already has a pending claim.' });
        }

        res.json({ success: true, message: 'Reward claim submitted for admin approval.' });
    } catch (err) {
        console.error('Error claiming job reward:', err);
        res.status(500).json({ error: 'Failed to claim reward.' });
    }
});
// --- END JOBS API ENDPOINTS ---


// --- NEW NOTIFICATION API ENDPOINTS ---
app.get('/api/notifications', requireLogin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching notifications:', err);
        res.status(500).json({ error: 'Failed to fetch notifications.' });
    }
});

app.post('/api/notifications/:notificationId/read', requireLogin, async (req, res) => {
    try {
        const { notificationId } = req.params;
        await pool.query(
            'UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2',
            [notificationId, req.user.id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('Error marking notification as read:', err);
        res.status(500).json({ error: 'Failed to update notification.' });
    }
});
// --- END NOTIFICATION API ENDPOINTS ---


app.get('/check-session', (req, res) => {
    if (req.session.userId) {
        res.json({ loggedIn: true, userId: req.session.userId, isAdmin: !!req.session.isAdmin });
    } else {
        res.json({ loggedIn: false });
    }
});

app.post('/signup', async (req, res) => {
    const { username, password, fullName, email, referralCode } = req.body;
    if (!username || !password || !fullName || !email) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (username === ADMIN_USERNAME) {
        return res.status(400).json({ error: 'Username reserved' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: 'Invalid email' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const existingUserResult = await client.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (existingUserResult.rows.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        let referrerId = null;
        if (referralCode) {
            const referrerResult = await client.query('SELECT id FROM users WHERE referral_code = $1', [referralCode]);
            if (referrerResult.rows.length > 0) {
                referrerId = referrerResult.rows[0].id;
            }
        }

        const passwordHash = await bcrypt.hash(password, saltRounds);
        const ownReferralCode = crypto.randomBytes(8).toString('hex');

        const newUserQuery = `INSERT INTO users (username, email, password_hash, full_name, referral_code) VALUES ($1, $2, $3, $4, $5) RETURNING id, username;`;
        const newUserResult = await client.query(newUserQuery, [username, email, passwordHash, fullName, ownReferralCode]);
        const { id: newUserId, username: newUsername } = newUserResult.rows[0];

        if (referrerId) {
            const referralInsertQuery = `INSERT INTO referrals (referrer_id, referred_id, type, status) VALUES ($1, $2, 'platform', 'completed') RETURNING id`;
            const referralResult = await client.query(referralInsertQuery, [referrerId, newUserId]);
            const newReferralId = referralResult.rows[0].id;

            const referralBonus = 5.00; // Example bonus
            await client.query('UPDATE users SET points = points + $1 WHERE id = $2', [referralBonus, referrerId]);
            await client.query('INSERT INTO referral_earnings (user_id, referral_id, amount) VALUES ($1, $2, $3)', [referrerId, newReferralId, referralBonus]);
        }
        
        await client.query('COMMIT');

        req.session.userId = newUsername;
        req.session.isAdmin = false;
        req.session.lastActivity = Date.now();
        
        res.status(201).json({ message: 'Signed up', userId: newUsername });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error during signup:', err);
        res.status(500).json({error: 'Server error during registration.'});
    } finally {
        client.release();
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Credentials required' });
    }

    if (username === ADMIN_USERNAME) {
        if (!ADMIN_PASSWORD_HASH) {
            return res.status(500).json({ error: 'Admin password not configured on server.' });
        }
        const adminMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
        if (adminMatch) {
            req.session.userId = username;
            req.session.isAdmin = true;
            req.session.lastActivity = Date.now();
            return res.json({ message: 'Logged in', userId: username, isAdmin: true });
        } else {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
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

// --- UPDATED PROFILE API ENDPOINT ---
app.get('/api/profile/:userId', requireLogin, async (req, res) => {
    const { userId } = req.params;

    if (userId !== req.session.userId && !req.session.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [userId]);
        const user = userResult.rows[0];
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const balanceQuery = `
            SELECT
                (COALESCE(SUM(credits), 0) - COALESCE(SUM(debits), 0)) AS current_balance
            FROM (
                SELECT SUM(public.parse_payout(q.reward)) AS credits, 0 AS debits FROM user_quests uq JOIN quests q ON uq.quest_id = q.id WHERE uq.user_id = $1
                UNION ALL
                SELECT SUM(je.amount) AS credits, 0 AS debits FROM job_earnings je WHERE je.user_id = $1
                UNION ALL
                SELECT SUM(re.amount) as credits, 0 as debits FROM referral_earnings re WHERE re.user_id = $1
                UNION ALL
                SELECT 0 AS credits, SUM(w.amount) AS debits FROM withdrawals w WHERE w.user_id = $1 AND (w.status = 'approved' OR w.status = 'pending')
            ) AS transactions;
        `;
        const balanceResult = await pool.query(balanceQuery, [user.id]);
        const calculatedBalance = parseFloat(balanceResult.rows[0].current_balance) || 0;

        if (Math.abs(calculatedBalance - parseFloat(user.points)) > 0.01) {
            console.warn(`User ${user.username} points out of sync. DB: ${user.points}, Calculated: ${calculatedBalance}. Updating.`);
            await pool.query('UPDATE users SET points = $1 WHERE id = $2', [calculatedBalance, user.id]);
        }


        const completedQuestsResult = await pool.query('SELECT COUNT(*) FROM user_quests WHERE user_id = $1', [user.id]);
        const questsCompleted = parseInt(completedQuestsResult.rows[0].count, 10);
        
        const jobsFinishedResult = await pool.query("SELECT COUNT(*) FROM job_completions WHERE user_id = $1", [user.id]);
        const jobsFinished = parseInt(jobsFinishedResult.rows[0].count, 10);

        const userSkillsResult = await pool.query(`
            SELECT DISTINCT em.skill_id, es.title AS skill_name
            FROM user_material_progress ump
            JOIN education_materials em ON ump.material_id = em.id
            JOIN education_skills es ON em.skill_id = es.id
            WHERE ump.user_id = $1
        `, [user.id]);

        const skillsInProgress = userSkillsResult.rows;

        const skillsWithProgress = await Promise.all(skillsInProgress.map(async (skill) => {
            const totalMaterialsResult = await pool.query('SELECT COUNT(*) FROM education_materials WHERE skill_id = $1', [skill.skill_id]);
            const totalMaterials = parseInt(totalMaterialsResult.rows[0].count, 10);
            
            const completedMaterialsResult = await pool.query(`
                SELECT COUNT(*) FROM user_material_progress ump
                JOIN education_materials em ON ump.material_id = em.id
                WHERE ump.user_id = $1 AND em.skill_id = $2
            `, [user.id, skill.skill_id]);
            const completedMaterials = parseInt(completedMaterialsResult.rows[0].count, 10);

            const progress = totalMaterials > 0 ? Math.round((completedMaterials / totalMaterials) * 100) : 0;
            return { name: skill.skill_name, progress };
        }));

        const historyQuery = `
            (SELECT 'Quest: ' || q.title AS desc, parse_payout(q.reward) AS amount, uq.completed_at AS date, 'credit' as type, 'completed' as status, NULL as transaction_hash FROM user_quests uq JOIN quests q ON uq.quest_id = q.id WHERE uq.user_id = $1)
            UNION ALL
            (SELECT 'Job Payment: ' || ap.title AS desc, je.amount, je.created_at AS date, 'credit' as type, 'completed' as status, NULL as transaction_hash FROM job_earnings je JOIN affiliate_programs ap ON je.program_id = ap.id WHERE je.user_id = $1)
            UNION ALL
            (SELECT 'Withdrawal' AS desc, w.amount, w.created_at AS date, 'debit' as type, w.status, w.transaction_hash FROM withdrawals w WHERE w.user_id = $1)
            ORDER BY date DESC LIMIT 20;
        `;
        const transactionHistoryResult = await pool.query(historyQuery, [user.id]);
        const transactions = transactionHistoryResult.rows.map(t => ({
            type: t.type,
            amount: parseFloat(t.amount).toFixed(2),
            desc: t.desc,
            date: new Date(t.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
            status: t.status,
            transaction_hash: t.transaction_hash
        }));
        
        const bookingsResult = await pool.query(`
            SELECT p.name, b.status, b.preferred_date AS date
            FROM bookings b
            JOIN professionals p ON b.professional_id = p.id
            WHERE b.user_id = $1 ORDER BY b.created_at DESC
        `, [user.id]);

        const earningsHistoryResult = await pool.query(`
            SELECT TO_CHAR(date_trunc('month', d), 'Mon') AS label, COALESCE(SUM(amount), 0) AS value
            FROM GENERATE_SERIES(date_trunc('year', CURRENT_DATE), date_trunc('year', CURRENT_DATE) + '1 year'::interval - '1 day'::interval, '1 month'::interval) d
            LEFT JOIN (
                SELECT completed_at AS earned_at, (SELECT parse_payout(reward) FROM quests q WHERE q.id = uq.quest_id) AS amount FROM user_quests uq WHERE uq.user_id = $1
                UNION ALL
                SELECT created_at AS earned_at, amount FROM job_earnings WHERE user_id = $1
            ) earnings ON date_trunc('month', d) = date_trunc('month', earnings.earned_at)
            GROUP BY date_trunc('month', d) ORDER BY date_trunc('month', d);
        `, [user.id]);
        
        res.json({
            user: {
                fullName: user.full_name,
                username: user.username,
                email: user.email,
                avatar: user.avatar || 'https://i.pravatar.cc/150?img=12',
                joinDate: new Date(user.created_at).toLocaleDateString('en-US', { month: 'short', year: 'numeric' }),
                bio: "Lifelong learner and digital creator. Exploring the worlds of design, code, and marketing. Let's connect!",
            },
            stats: {
                totalEarnings: calculatedBalance,
                questsCompleted: questsCompleted,
                jobsFinished: jobsFinished,
                skillsInProgress: skillsWithProgress.length
            },
            earningsChart: {
                labels: earningsHistoryResult.rows.map(r => r.label),
                data: earningsHistoryResult.rows.map(r => parseFloat(r.value))
            },
            recentActivity: transactions.slice(0, 5).map(item => ({
                icon: item.type === 'credit' ? 'fa-check-circle' : 'fa-wallet',
                color: item.type === 'credit' ? 'green' : 'red',
                text: `${item.desc} ($${item.amount})`,
                time: item.date
            })),
            mySkills: skillsWithProgress,
            expertBookings: bookingsResult.rows,
            transactions: transactions,
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
        case 'all': interval = null; seriesStart = `(SELECT MIN(created_at) FROM users WHERE username = $1)`; break;
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
                SELECT created_at AS earned_at, amount FROM job_earnings WHERE user_id = $1
            ) earnings ON date_trunc('day', d) = date_trunc('day', earnings.earned_at)
            GROUP BY 1 ORDER BY 1;
        `;
        const earningsResult = await pool.query(query, [userDbId]);
        res.json({
            labels: earningsResult.rows.map(r => r.label),
            data: earningsResult.rows.map(r => parseFloat(r.value))
        });
    } catch(err) {
        console.error("Error fetching earnings history:", err);
        res.status(500).json({error: 'Failed to fetch earnings history'});
    }
});

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
        const pendingWithdrawalsResult = await pool.query("SELECT COUNT(*) FROM withdrawals WHERE user_id = $1 AND status = 'pending'", [user.id]);

        res.json({
            totalEarnings: user.points || 0,
            questsCompleted: completedQuestsResult.rows,
            pendingWithdrawals: parseInt(pendingWithdrawalsResult.rows[0].count, 10)
        });
    } catch (err) {
        console.error('Quest-overview error:', err);
        res.status(500).json({ error: 'Failed to fetch quest overview' });
    }
});

app.post('/withdraw', requireLogin, async (req, res) => {
    const { amount, walletAddress, chain } = req.body;
    const userDbId = req.user.id;
    const withdrawalAmount = parseFloat(amount);

    if (isNaN(withdrawalAmount) || withdrawalAmount <= 0) {
        return res.status(400).json({ error: 'Invalid withdrawal amount.' });
    }
    if (!walletAddress || !chain) {
        return res.status(400).json({ error: 'Wallet address and chain are required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const userResult = await pool.query('SELECT points FROM users WHERE id = $1 FOR UPDATE', [userDbId]);
        const user = userResult.rows[0];

        if (!user || user.points < withdrawalAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Insufficient balance.' });
        }

        await client.query('UPDATE users SET points = points - $1 WHERE id = $2', [withdrawalAmount, userDbId]);

        await client.query(
            'INSERT INTO withdrawals (user_id, amount, wallet_address, chain, status) VALUES ($1, $2, $3, $4, $5)',
            [userDbId, withdrawalAmount, walletAddress, chain, 'pending']
        );

        await client.query('COMMIT');
        res.json({ message: 'Withdrawal request submitted successfully! It is now pending approval.' });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Withdrawal error:', err);
        res.status(500).json({ error: 'Failed to process withdrawal request.' });
    } finally {
        client.release();
    }
});

app.get('/withdrawal-history', requireLogin, async (req, res) => {
    const userId = req.user.id;
    try {
        const historyResult = await pool.query(
            'SELECT amount, status, transaction_hash, created_at FROM withdrawals WHERE user_id = $1 ORDER BY created_at DESC', 
            [userId]
        );
        res.json({ history: historyResult.rows });
    } catch (err) {
        console.error('Error fetching withdrawal history:', err);
        res.status(500).json({ error: 'Failed to fetch withdrawal history.' });
    }
});


app.get('/quests', requireLogin, async (req, res) => {
    try {
        const userId = req.user.id;

        const questsResult = await pool.query(`
            SELECT 
                q.*,
                COALESCE(qr.referral_count, 0) AS user_referral_count
            FROM 
                quests q
            LEFT JOIN (
                SELECT 
                    quest_id, 
                    COUNT(*) AS referral_count
                FROM 
                    referrals
                WHERE 
                    referrer_id = $1 AND type = 'quest' AND status = 'completed'
                GROUP BY 
                    quest_id
            ) qr ON q.id = qr.quest_id
            ORDER BY 
                q.id ASC;
        `, [userId]);

        res.json({ quests: questsResult.rows });
    } catch (err) {
        console.error('Error reading quests:', err);
        res.json({ quests: [] });
    }
});

// Use the questUpload middleware for this route
app.post('/api/quests', requireAdmin, questUpload, async (req, res) => {
    const { title, description, reward, status, start_time, end_time, max_participants } = req.body;
    // Access uploaded files from req.files object.
    const backgroundUrl = req.files.questBackground ? `/uploads/${req.files.questBackground[0].filename}` : null;
    const bannerUrl = req.files.questBanner ? `/uploads/${req.files.questBanner[0].filename}` : null;

    try {
        const newQuest = await pool.query(
            'INSERT INTO quests (title, description, reward, status, start_time, end_time, quiz_background_url, card_banner_url, max_participants) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
            [title, description, reward, status, start_time || null, end_time || null, backgroundUrl, bannerUrl, max_participants || null]
        );
        res.status(201).json(newQuest.rows[0]);
    } catch (err) {
        console.error('Error creating quest:', err);
        res.status(500).json({ error: 'Failed to create quest' });
    }
});

// Use the questUpload middleware for this route as well
app.put('/api/quests/:id', requireAdmin, questUpload, async (req, res) => {
    const { id } = req.params;
    const { title, description, reward, status, start_time, end_time, max_participants } = req.body;

    try {
        const oldQuestResult = await pool.query('SELECT quiz_background_url, card_banner_url FROM quests WHERE id = $1', [id]);
        const oldUrls = oldQuestResult.rows[0];

        // Handle new background upload
        if (req.files.questBackground && oldUrls?.quiz_background_url) {
            await fs.unlink(path.join(__dirname, 'public', oldUrls.quiz_background_url)).catch(e => console.error("Failed to delete old background file:", e));
        }
        
        // Handle new banner upload
        if (req.files.questBanner && oldUrls?.card_banner_url) {
            await fs.unlink(path.join(__dirname, 'public', oldUrls.card_banner_url)).catch(e => console.error("Failed to delete old banner file:", e));
        }

        const backgroundUrl = req.files.questBackground ? `/uploads/${req.files.questBackground[0].filename}` : undefined;
        const bannerUrl = req.files.questBanner ? `/uploads/${req.files.questBanner[0].filename}` : undefined;

        let queryText = 'UPDATE quests SET title = $1, description = $2, reward = $3, status = $4, start_time = $5, end_time = $6, max_participants = $7';
        const queryParams = [title, description, reward, status, start_time || null, end_time || null, max_participants || null];
        
        if (backgroundUrl !== undefined) {
            queryText += `, quiz_background_url = $${queryParams.length + 1}`;
            queryParams.push(backgroundUrl);
        }
        if (bannerUrl !== undefined) {
            queryText += `, card_banner_url = $${queryParams.length + 1}`;
            queryParams.push(bannerUrl);
        }
        
        queryText += ` WHERE id = $${queryParams.length + 1} RETURNING *`;
        queryParams.push(id);

        const updatedQuest = await pool.query(queryText, queryParams);

        if (updatedQuest.rows.length === 0) {
            return res.status(404).json({ error: 'Quest not found' });
        }
        res.json(updatedQuest.rows[0]);
    } catch (err) {
        console.error('Error updating quest:', err);
        res.status(500).json({ error: 'Failed to update quest' });
    }
});


app.delete('/api/quests/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const oldQuestResult = await pool.query('SELECT quiz_background_url, card_banner_url FROM quests WHERE id = $1', [id]);
        const oldUrls = oldQuestResult.rows[0];
        if (oldUrls?.quiz_background_url) {
            await fs.unlink(path.join(__dirname, 'public', oldUrls.quiz_background_url)).catch(e => console.error("Failed to delete background file on quest deletion:", e));
        }
        if (oldUrls?.card_banner_url) {
            await fs.unlink(path.join(__dirname, 'public', oldUrls.card_banner_url)).catch(e => console.error("Failed to delete banner file on quest deletion:", e));
        }

        const deleteOp = await pool.query('DELETE FROM quests WHERE id = $1 RETURNING *', [id]);
        if (deleteOp.rowCount === 0) {
            return res.status(404).json({ error: 'Quest not found' });
        }
        res.json({ message: 'Quest deleted successfully' });
    } catch (err) {
        console.error('Error deleting quest:', err);
        res.status(500).json({ error: 'Failed to delete quest' });
    }
});

// [NEW] Endpoint to get participants for a quest
app.get('/api/admin/quests/:questId/participants', requireAdmin, async (req, res) => {
    const { questId } = req.params;
    try {
        const query = `
            SELECT u.id, u.username, u.full_name, u.email, uq.completed_at
            FROM user_quests uq
            JOIN users u ON uq.user_id = u.id
            WHERE uq.quest_id = $1
            ORDER BY uq.completed_at DESC;
        `;
        const result = await pool.query(query, [questId]);
        res.json({ participants: result.rows });
    } catch (err) {
        console.error('Error fetching quest participants:', err);
        res.status(500).json({ error: 'Failed to fetch quest participants.' });
    }
});

// [NEW] Endpoint to remove a participant from a quest
app.post('/api/admin/quests/participants/remove', requireAdmin, async (req, res) => {
    const { userId, questId, reason } = req.body;
    if (!userId || !questId || !reason) {
        return res.status(400).json({ error: 'User ID, Quest ID, and reason are required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const userQuestResult = await client.query('SELECT * FROM user_quests WHERE user_id = $1 AND quest_id = $2', [userId, questId]);
        if (userQuestResult.rowCount === 0) {
            throw new Error('User has not completed this quest.');
        }

        const questResult = await client.query('SELECT title, reward FROM quests WHERE id = $1', [questId]);
        if (questResult.rowCount === 0) {
            throw new Error('Quest not found.');
        }
        const quest = questResult.rows[0];
        
        const rewardAmount = parsePayout(quest.reward);

        // Deduct points
        await client.query('UPDATE users SET points = points - $1 WHERE id = $2', [rewardAmount, userId]);

        // Remove completion record
        await client.query('DELETE FROM user_quests WHERE user_id = $1 AND quest_id = $2', [userId, questId]);

        // Notify user
        const message = `Your completion of the quest "${quest.title}" has been revoked by an administrator. Reason: ${reason}. The reward of ${rewardAmount.toFixed(2)} has been deducted from your account.`;
        await client.query('INSERT INTO notifications (user_id, message) VALUES ($1, $2)', [userId, message]);

        await client.query('COMMIT');
        res.json({ success: true, message: 'Participant removed and notified successfully.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error removing quest participant:', err);
        res.status(500).json({ error: err.message || 'Failed to remove participant.' });
    } finally {
        client.release();
    }
});

// =============================================================================
// === START OF UPDATED QUEST STAGE ENDPOINTS ===
// =============================================================================

// UPDATED - To fetch ordered quest stages
app.get('/api/quests/:questId/questions', requireLogin, async (req, res) => {
    const { questId } = req.params;
    try {
        // We now select from the new table and order by the challenge_order
        const result = await pool.query('SELECT * FROM quest_questions WHERE quest_id = $1 ORDER BY challenge_order ASC', [questId]);
        res.json({ questions: result.rows });
    } catch (err) {
        console.error('Error fetching questions:', err);
        res.status(500).json({ error: 'Failed to fetch questions' });
    }
});

// UPDATED - To create a new quest stage
app.post('/api/quests/:questId/questions', requireAdmin, async (req, res) => {
    const { questId } = req.params;
    // The request body now sends our new, flexible structure
    const { challenge_order, challenge_type, challenge_data } = req.body;
    try {
        const newQuestion = await pool.query(
            'INSERT INTO quest_questions (quest_id, challenge_order, challenge_type, challenge_data) VALUES ($1, $2, $3, $4) RETURNING *',
            [questId, challenge_order, challenge_type, challenge_data]
        );
        res.status(201).json(newQuestion.rows[0]);
    } catch (err) {
        console.error('Error creating question:', err);
        res.status(500).json({ error: 'Failed to create question' });
    }
});

// UPDATED - To update an existing quest stage
app.put('/api/quests/:questId/questions/:questionId', requireAdmin, async (req, res) => {
    const { questionId } = req.params;
    // The request body also sends the new structure for updates
    const { challenge_order, challenge_type, challenge_data } = req.body;
    try {
        const updatedQuestion = await pool.query(
            'UPDATE quest_questions SET challenge_order = $1, challenge_type = $2, challenge_data = $3 WHERE id = $4 RETURNING *',
            [challenge_order, challenge_type, challenge_data, questionId]
        );
        if (updatedQuestion.rows.length === 0) {
            return res.status(404).json({ error: 'Question not found' });
        }
        res.json(updatedQuestion.rows[0]);
    } catch (err) {
        console.error('Error updating question:', err);
        res.status(500).json({ error: 'Failed to update question' });
    }
});

app.delete('/api/quests/:questId/questions/:questionId', requireAdmin, async (req, res) => {
    const { questionId } = req.params;
    try {
        const deleteOp = await pool.query('DELETE FROM quest_questions WHERE id = $1 RETURNING *', [questionId]);
        if (deleteOp.rowCount === 0) {
            return res.status(404).json({ error: 'Question not found' });
        }
        res.json({ message: 'Question deleted successfully' });
    } catch (err) {
        console.error('Error deleting question:', err);
        res.status(500).json({ error: 'Failed to delete question' });
    }
});

// UPDATED - To handle submission of multi-stage quests
app.post('/submit-quiz/:questId', requireLogin, async (req, res) => {
    const questId = parseInt(req.params.questId, 10);
    const userDbId = req.user.id;
    // The 'answers' body is now an object of responses, not an array
    const { answers } = req.body;

    // We now validate for an object
    if (typeof answers !== 'object' || answers === null) {
        return res.status(400).json({ error: 'Invalid answers format.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const questResult = await client.query('SELECT * FROM quests WHERE id = $1 FOR UPDATE', [questId]);
        const quest = questResult.rows[0];
        if (!quest) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Quest not found.' });
        }
        if (quest.max_participants !== null) {
            const participantCountResult = await client.query('SELECT COUNT(*) FROM user_quests WHERE quest_id = $1', [questId]);
            const participantCount = parseInt(participantCountResult.rows[0].count, 10);
            if (participantCount >= quest.max_participants) {
                await client.query('ROLLBACK');
                return res.status(403).json({ error: 'This quest has reached its maximum number of participants.' });
            }
        }

        const existingCompletion = await pool.query(
            'SELECT 1 FROM user_quests WHERE user_id = $1 AND quest_id = $2',
            [userDbId, questId]
        );
        if (existingCompletion.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'You have already completed this quest.' });
        }
        
        // Get the total number of challenges for this quest
        const questionsResult = await client.query(
            'SELECT COUNT(*) FROM quest_questions WHERE quest_id = $1',
            [questId]
        );
        const totalChallenges = parseInt(questionsResult.rows[0].count, 10);

        // Check if the number of answers submitted is at least the number of challenges.
        // This assumes every stage requires an answer. For now, this is a safe validation.
        const allAnswered = Object.keys(answers).length >= totalChallenges;
        
        if (allAnswered) {
            const rewardValue = parsePayout(quest.reward);
            await client.query('UPDATE users SET points = points + $1 WHERE id = $2', [rewardValue, userDbId]);
            await client.query(
                'INSERT INTO user_quests (user_id, quest_id, completed_at) VALUES ($1, $2, NOW())',
                [userDbId, questId]
            );
             const referralResult = await client.query(
                `UPDATE referrals SET status = 'completed' 
                 WHERE referred_id = $1 AND quest_id = $2 AND type = 'quest' AND status = 'pending' 
                 RETURNING id, referrer_id`,
                [userDbId, questId]
            );

            if (referralResult.rows.length > 0) {
                const { id: referralId, referrer_id: referrerId } = referralResult.rows[0];
                const referralBonus = 2.00;
                await client.query('UPDATE users SET points = points + $1 WHERE id = $2', [referralBonus, referrerId]);
                await client.query('INSERT INTO referral_earnings (user_id, referral_id, amount) VALUES ($1, $2, $3)', [referrerId, referralId, referralBonus]);
            }

            await client.query('COMMIT');

            const referralLink = `${process.env.BASE_URL || `http://localhost:${PORT}`}/referral?questId=${questId}&referrerId=${encodeURIComponent(req.user.username)}`;
            
            res.json({
                success: true,
                message: "Quest completed successfully!",
                reward: quest.reward,
                referralLink
            });

        } else {
            await client.query('ROLLBACK');
            res.json({
                success: false,
                message: "Please answer all questions to complete the quest."
            });
        }

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error submitting quiz:', err);
        res.status(500).json({ error: err.message || 'An error occurred while submitting the quest.' });
    } finally {
        client.release();
    }
});

// =============================================================================
// === END OF UPDATED QUEST STAGE ENDPOINTS ===
// =============================================================================


app.get('/quests/:questId/responses', requireAdmin, async (req, res) => {
    res.json({});
});

app.get('/api/referrals', requireLogin, async (req, res) => {
    const userId = req.user.id;
    try {
        const referralStatsQuery = `
            SELECT 
                (SELECT COUNT(*) FROM referrals WHERE referrer_id = $1) as total_referrals,
                (SELECT SUM(amount) FROM referral_earnings WHERE user_id = $1) as total_earnings
        `;
        const referralStatsResult = await pool.query(referralStatsQuery, [userId]);

        const referralsQuery = `
            SELECT r.type, r.status, u.username as referred_username, q.title as quest_title 
            FROM referrals r 
            JOIN users u ON r.referred_id = u.id 
            LEFT JOIN quests q ON r.quest_id = q.id 
            WHERE r.referrer_id = $1 
            ORDER BY r.created_at DESC
        `;
        const referralsResult = await pool.query(referralsQuery, [userId]);
        
        res.json({
            stats: {
                totalReferrals: parseInt(referralStatsResult.rows[0].total_referrals, 10) || 0,
                totalEarnings: parseFloat(referralStatsResult.rows[0].total_earnings) || 0
            },
            referrals: referralsResult.rows
        });
    } catch (err) {
        console.error('Error fetching referral data:', err);
        res.status(500).json({ error: 'Failed to fetch referral data' });
    }
});


app.get('/generate-referral-link', requireLogin, async (req, res) => {
    const { questId } = req.query;
    const user = req.user;

    try {
        if (!user.referral_code) {
            const newReferralCode = crypto.randomBytes(8).toString('hex');
            await pool.query('UPDATE users SET referral_code = $1 WHERE id = $2', [newReferralCode, user.id]);
            user.referral_code = newReferralCode;
        }

        const baseUrl = process.env.BASE_URL || `https://rewardrushapp.onrender.com`;
        let referralLink = `${baseUrl}/auth.html?referralCode=${user.referral_code}`;
        if (questId) {
            referralLink += `&questId=${questId}`;
        }
        res.json({ referralLink });
    } catch (err) {
        console.error('Error generating referral link:', err);
        res.status(500).json({ error: 'Could not generate referral link' });
    }
});


app.get('/referral', async (req, res) => {
    const { questId, referralCode } = req.query;
    try {
        if (referralCode) {
            const referrerResult = await pool.query('SELECT id FROM users WHERE referral_code = $1', [referralCode]);
            if (referrerResult.rows.length > 0) {
                const referrerId = referrerResult.rows[0].id;
                if (req.session.userId) {
                    const loggedInUserResult = await pool.query('SELECT id FROM users WHERE username = $1', [req.session.userId]);
                    const loggedInUserId = loggedInUserResult.rows[0].id;
                    if (loggedInUserId !== referrerId) {
                        await pool.query(
                            `INSERT INTO referrals (referrer_id, referred_id, quest_id, type) 
                             VALUES ($1, $2, $3, 'quest') 
                             ON CONFLICT (referrer_id, referred_id, quest_id) DO NOTHING`,
                            [referrerId, loggedInUserId, questId]
                        );
                    }
                }
            }
        }

        const questResult = await pool.query('SELECT * FROM quests WHERE id = $1', [questId]);
        const quest = questResult.rows[0];
        if (!quest || !quest.quiz_page) return res.status(404).json({ error: 'Quest not found' });
        
        let redirectUrl = quest.quiz_page;
        const params = new URLSearchParams();
        if (referralCode) {
            params.append('referralCode', referralCode);
        }
        if (questId) {
            params.append('questId', questId);
        }
        if (params.toString()) {
            redirectUrl += `?${params.toString()}`;
        }
        res.redirect(redirectUrl);
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

// --- ADMIN JOBS (AFFILIATE PROGRAMS) API ENDPOINTS ---
app.get('/api/admin/jobs', requireAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                ap.*,
                COALESCE(ac.participants_count, 0) AS participants
            FROM 
                affiliate_programs ap
            LEFT JOIN (
                SELECT 
                    program_id, 
                    COUNT(DISTINCT user_id) as participants_count 
                FROM 
                    user_jobs 
                GROUP BY 
                    program_id
            ) ac ON ap.id = ac.program_id
            ORDER BY 
                ap.id ASC;
        `;
        const result = await pool.query(query);
        res.json({ programs: result.rows });
    } catch (err) {
        console.error('Error fetching admin jobs data:', err);
        res.status(500).json({ error: 'Failed to fetch jobs data' });
    }
});

app.get('/api/admin/job-requests', requireAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                uj.id,
                uj.status,
                u.username,
                ap.title as program_title,
                ap.payout,
                uj.submission_link,
                uj.onboarding_link,
                uj.tracking_link,
                uj.current_claim_amount,
                uj.cumulative_reward_paid
            FROM user_jobs uj
            JOIN users u ON uj.user_id = u.id
            JOIN affiliate_programs ap ON uj.program_id = ap.id
            WHERE uj.status IN ('pending_links', 'reward_pending', 'pending_review')
            ORDER BY uj.updated_at ASC;
        `;
        const result = await pool.query(query);
        res.json({ requests: result.rows });
    } catch (err) {
        console.error('Error fetching job requests:', err);
        res.status(500).json({ error: 'Failed to fetch job requests.' });
    }
});


app.post('/api/admin/job-requests/:requestId/send-links', requireAdmin, async (req, res) => {
    const { requestId } = req.params;
    const { onboardingLink, trackingLink } = req.body;

    if (!onboardingLink) {
        return res.status(400).json({ error: 'Onboarding link is required.' });
    }

    try {
        const result = await pool.query(
            "UPDATE user_jobs SET onboarding_link = $1, tracking_link = $2, status = 'active', updated_at = NOW() WHERE id = $3 AND status = 'pending_links' RETURNING *",
            [onboardingLink, trackingLink, requestId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Request not found or already processed.' });
        }
        res.json({ success: true, message: 'Links sent and job activated.' });
    } catch (err) {
        console.error('Error sending links:', err);
        res.status(500).json({ error: 'Failed to send links.' });
    }
});

app.post('/api/admin/job-requests/:requestId/approve-reward', requireAdmin, async (req, res) => {
    const { requestId } = req.params;
    const { editedAmount } = req.body;
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const jobRequestResult = await client.query(
            "SELECT * FROM user_jobs WHERE id = $1 AND status = 'reward_pending' FOR UPDATE", 
            [requestId]
        );

        if (jobRequestResult.rows.length === 0) {
            throw new Error('Job request not found or not pending reward.');
        }
        
        const job = jobRequestResult.rows[0];
        const { user_id, program_id, current_claim_amount, cumulative_reward_paid, is_final_claim } = job;

        const amountToPay = editedAmount ? parseFloat(editedAmount) : parseFloat(current_claim_amount);
        if (isNaN(amountToPay) || amountToPay <= 0) {
            throw new Error('Invalid payment amount provided.');
        }
        
        await client.query('UPDATE users SET points = points + $1 WHERE id = $2', [amountToPay, user_id]);

        await client.query(
            'INSERT INTO job_earnings (user_id, program_id, user_job_id, amount, is_final_payment) VALUES ($1, $2, $3, $4, $5)',
            [user_id, program_id, requestId, amountToPay, is_final_claim]
        );

        if (is_final_claim) {
            const totalRewardForAttempt = parseFloat(cumulative_reward_paid) + amountToPay;
            await client.query(
                'INSERT INTO job_completions (user_id, program_id, reward_amount) VALUES ($1, $2, $3)',
                [user_id, program_id, totalRewardForAttempt]
            );
            await client.query('DELETE FROM user_jobs WHERE id = $1', [requestId]);
        } else {
            const newCumulative = parseFloat(cumulative_reward_paid) + amountToPay;
            await client.query(
                "UPDATE user_jobs SET status = 'active', cumulative_reward_paid = $1, current_claim_amount = NULL, is_final_claim = false, updated_at = NOW() WHERE id = $2", 
                [newCumulative, requestId]
            );
        }

        await client.query('COMMIT');
        res.json({ success: true, message: 'Reward approved and points awarded.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error approving reward:', err);
        res.status(500).json({ error: err.message || 'Failed to approve reward.' });
    } finally {
        client.release();
    }
});

app.post('/api/admin/job-requests/:requestId/review', requireAdmin, async (req, res) => {
    const { requestId } = req.params;
    const { approved, rejectionReason, editedAmount } = req.body;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const jobRequestResult = await client.query(
            "SELECT * FROM user_jobs WHERE id = $1 AND (status = 'pending_review' OR status = 'reward_pending') FOR UPDATE", 
            [requestId]
        );
        if (jobRequestResult.rows.length === 0) {
            throw new Error('Job request not found or not pending review.');
        }

        const job = jobRequestResult.rows[0];
        const { user_id, program_id, current_claim_amount, cumulative_reward_paid, is_final_claim } = job;

        if (approved) {
            const amountToPay = editedAmount ? parseFloat(editedAmount) : parseFloat(current_claim_amount);
            if (isNaN(amountToPay) || amountToPay <= 0) {
                throw new Error('A valid payment amount is required for approval.');
            }

            await client.query('UPDATE users SET points = points + $1 WHERE id = $2', [amountToPay, user_id]);
            
            await client.query(
                'INSERT INTO job_earnings (user_id, program_id, user_job_id, amount, is_final_payment) VALUES ($1, $2, $3, $4, $5)',
                [user_id, program_id, requestId, amountToPay, is_final_claim]
            );

            if (is_final_claim) {
                const totalRewardForAttempt = parseFloat(cumulative_reward_paid) + amountToPay;
                await client.query(
                    'INSERT INTO job_completions (user_id, program_id, reward_amount) VALUES ($1, $2, $3)',
                    [user_id, program_id, totalRewardForAttempt]
                );
                await client.query('DELETE FROM user_jobs WHERE id = $1', [requestId]);
            } else {
                const newCumulative = parseFloat(cumulative_reward_paid) + amountToPay;
                await client.query(
                    "UPDATE user_jobs SET status = 'active', cumulative_reward_paid = $1, current_claim_amount = NULL, is_final_claim = false, submission_link = NULL, updated_at = NOW() WHERE id = $2",
                    [newCumulative, requestId]
                );
            }
             res.json({ success: true, message: 'Submission has been approved.' });
        } else {
            if (!rejectionReason || rejectionReason.trim() === '') {
                 return res.status(400).json({ error: 'A rejection reason is required.' });
            }
            await client.query(
                "UPDATE user_jobs SET status = 'rejected', rejection_reason = $1, current_claim_amount = NULL, is_final_claim = false, updated_at = NOW() WHERE id = $2", 
                [rejectionReason, requestId]
            );
             res.json({ success: true, message: 'Submission has been rejected.' });
        }

        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error reviewing submission:', err);
        res.status(500).json({ error: err.message || 'Failed to review submission.' });
    } finally {
        client.release();
    }
});


app.post('/api/admin/jobs', requireAdmin, async (req, res) => {
    const { title, category, payout, destination_url, guidelines, details, pros, cons, brand_website, social_links, max_participants, status } = req.body;
    try {
        const newProgram = await pool.query(
            'INSERT INTO affiliate_programs (title, category, payout, destination_url, guidelines, details, pros, cons, brand_website, social_links, max_participants, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *',
            [title, category, payout, destination_url, guidelines, details, pros, cons, brand_website, social_links, max_participants || null, status]
        );
        res.status(201).json(newProgram.rows[0]);
    } catch (err) {
        console.error('Error creating affiliate program:', err);
        res.status(500).json({ error: 'Failed to create affiliate program' });
    }
});

app.put('/api/admin/jobs/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { title, category, payout, destination_url, guidelines, details, pros, cons, brand_website, social_links, max_participants, status } = req.body;
    try {
        const updatedProgram = await pool.query(
            'UPDATE affiliate_programs SET title = $1, category = $2, payout = $3, destination_url = $4, guidelines = $5, details = $6, pros = $7, cons = $8, brand_website = $9, social_links = $10, max_participants = $11, status = $12 WHERE id = $13 RETURNING *',
            [title, category, payout, destination_url, guidelines, details, pros, cons, brand_website, social_links, max_participants || null, status, id]
        );
        if (updatedProgram.rows.length === 0) {
            return res.status(404).json({ error: 'Affiliate program not found' });
        }
        res.json(updatedProgram.rows[0]);
    } catch (err) {
        console.error('Error updating affiliate program:', err);
        res.status(500).json({ error: 'Failed to update affiliate program' });
    }
});


app.delete('/api/admin/jobs/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('DELETE FROM job_earnings WHERE program_id = $1', [id]);
        await client.query('DELETE FROM job_completions WHERE program_id = $1', [id]);
        await client.query('DELETE FROM user_jobs WHERE program_id = $1', [id]);
        await client.query('DELETE FROM affiliate_clicks WHERE program_id = $1', [id]);
        await client.query('DELETE FROM conversions WHERE program_id = $1', [id]);
        const deleteOp = await client.query('DELETE FROM affiliate_programs WHERE id = $1 RETURNING *', [id]);
        await client.query('COMMIT');
        
        if (deleteOp.rowCount === 0) {
            return res.status(404).json({ error: 'Affiliate program not found' });
        }
        res.json({ message: 'Affiliate program and related data deleted successfully' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error deleting affiliate program:', err);
        res.status(500).json({ error: 'Failed to delete affiliate program' });
    } finally {
        client.release();
    }
});

// NEW: Endpoint for removing a participant and sending a notification
app.post('/api/admin/jobs/participants/remove', requireAdmin, async (req, res) => {
    const { userJobId, reason } = req.body;
    if (!userJobId || !reason) {
        return res.status(400).json({ error: 'User Job ID and reason are required.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Get details for the notification before deleting
        const jobDetailsResult = await client.query(`
            SELECT uj.user_id, ap.title AS program_title
            FROM user_jobs uj
            JOIN affiliate_programs ap ON uj.program_id = ap.id
            WHERE uj.id = $1
        `, [userJobId]);

        if (jobDetailsResult.rows.length === 0) {
            throw new Error('Participant record not found.');
        }
        const { user_id, program_title } = jobDetailsResult.rows[0];

        // Delete the participant's job record
        const deleteResult = await client.query('DELETE FROM user_jobs WHERE id = $1', [userJobId]);
        if (deleteResult.rowCount === 0) {
            throw new Error('Could not remove participant.');
        }

        // Create a notification for the user
        const message = `You have been removed from the job "${program_title}" by an administrator. Reason: ${reason}`;
        await client.query(
            'INSERT INTO notifications (user_id, message) VALUES ($1, $2)',
            [user_id, message]
        );

        await client.query('COMMIT');
        res.json({ success: true, message: 'Participant removed and notified.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error removing participant:', err);
        res.status(500).json({ error: err.message || 'Failed to remove participant.' });
    } finally {
        client.release();
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
        const programResult = await pool.query('SELECT * FROM affiliate_programs WHERE id = $1', [programId]);
        const program = programResult.rows[0];
        if (!program) {
             await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Program not found.' });
        }
        const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [affiliateId]);
        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({error: 'Affiliate user not found'});
        }
        const affiliateDbId = userResult.rows[0].id;
        const payoutAmount = parsePayout(program.payout); 
        
        await pool.query(
            `INSERT INTO user_jobs (user_id, program_id, status, current_claim_amount, is_final_claim) 
             VALUES ($1, $2, 'reward_pending', $3, true)
             ON CONFLICT (user_id, program_id) DO UPDATE SET status = 'reward_pending', current_claim_amount = $3, is_final_claim = true`,
            [affiliateDbId, programId, payoutAmount]
        );

        await client.query('COMMIT');
        res.status(201).json({ message: 'Conversion submitted for admin approval.' });
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
        const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [affiliateId]);
        const userId = userResult.rows[0].id;

        const clicksResult = await pool.query('SELECT COUNT(*) FROM affiliate_clicks WHERE affiliate_username = $1', [affiliateId]);
        const earningsResult = await pool.query(`
            SELECT COUNT(*) as count, SUM(amount) as earnings 
            FROM job_earnings
            WHERE user_id = $1
        `, [userId]);

        res.json({
            totalClicks: parseInt(clicksResult.rows[0].count, 10),
            totalConversions: parseInt(earningsResult.rows[0].count, 10),
            totalEarnings: parseFloat(earningsResult.rows[0].earnings) || 0,
        });
    } catch(err) {
        console.error("Error fetching affiliate stats:", err);
        res.status(500).json({error: 'Could not fetch stats.'});
    }
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
app.get('/post-a-job.html', requireLogin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'post-a-job.html')));
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

app.post('/unblock-user', requireAdmin, async (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username required' });
    try {
        const result = await pool.query('UPDATE users SET blocked = false WHERE username = $1 RETURNING *', [username]);
        if(result.rowCount === 0) return res.status(404).json({error: 'User not found'});
        res.json({ message: `User ${username} unblocked` });
    } catch(err) {
        console.error("Error unblocking user:", err);
        res.status(500).json({error: 'Failed to unblock user'});
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
        res.json(expert);
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

app.post('/api/users/:userId/settings', requireLogin, async (req, res) => {
    const { userId } = req.params;
    const { settings } = req.body;

    if (req.params.userId !== req.session.userId.toString()) {
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
});

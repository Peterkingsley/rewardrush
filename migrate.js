// FINAL MIGRATION SCRIPT
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

// --- Load Environment Variables ---
require('dotenv').config();

// --- DATABASE CONNECTION ---
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Helper to read JSON files safely
function readJsonFile(fileName) {
  const filePath = path.join(__dirname, fileName);
  if (!fs.existsSync(filePath)) {
    console.log(`\n[Skipping] File not found: ${fileName}`);
    return null;
  }
  const data = fs.readFileSync(filePath, 'utf8').trim();
  if (data === '' || data === '{}' || data === '[]') {
    console.log(`\n[Skipping] File is empty: ${fileName}`);
    return null;
  }
  return JSON.parse(data);
}

async function migrateUsers() {
  const usersObject = readJsonFile('users.json');
  if (!usersObject) return;
  const usersList = Object.entries(usersObject);
  console.log(`\nMigrating ${usersList.length} users...`);
  for (const [username, user] of usersList) {
    // CORRECTED QUERY: Added full_name to the query
    const query = `INSERT INTO users (username, email, password_hash, full_name, twitter_handle, wallet_address, referral_code, points) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (email) DO NOTHING;`;
    // CORRECTED VALUES: Added user.fullName to the values array
    const values = [username, user.email, user.passwordHash, user.fullName, user.twitterHandle, user.walletAddress, user.referralCode, user.totalEarnings || 0];
    try {
      await pool.query(query, values);
    } catch (err) {
      console.error(`  Error migrating user ${username}:`, err.message);
    }
  }
  console.log('User migration complete.');
}

async function migrateQuests() {
    const data = readJsonFile('quests.json');
    if (!data || !data.quests) return;
    const quests = data.quests;
    console.log(`\nMigrating ${quests.length} quests...`);
    for (const quest of quests) {
        const questQuery = `INSERT INTO quests (id, title, description, reward, status, start_time, end_time, participants) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, description = EXCLUDED.description;`;
        const questValues = [quest.id, quest.title, quest.description, quest.reward, quest.status, quest.startTime, quest.endTime, quest.participants];
        try {
            await pool.query(questQuery, questValues);
            if (quest.questions && quest.questions.length > 0) {
                for (const q of quest.questions) {
                    const questionQuery = `INSERT INTO quest_questions (quest_id, question_id, question_type, question_text, options, correct_answer) VALUES ($1, $2, $3, $4, $5, $6);`;
                    const questionValues = [quest.id, q.id, q.type, q.text, q.options ? JSON.stringify(q.options) : null, q.correctAnswer];
                    await pool.query(questionQuery, questionValues);
                }
            }
        } catch (err) {
            console.error(`  Error migrating quest ID ${quest.id}:`, err.message);
        }
    }
    console.log('Quest migration complete.');
}


async function migrateAffiliatePrograms() {
    const data = readJsonFile('affiliate-programs.json');
    if (!data || !data.programs) return;
    const programs = data.programs;
    console.log(`\nMigrating ${programs.length} affiliate programs...`);
    for (const program of programs) {
        const query = `INSERT INTO affiliate_programs (id, category, title, guidelines, details, pros, cons, payout, destination_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title;`;
        const values = [program.id, program.category, program.title, program.guidelines, program.details, program.pros, program.cons, program.payout, program.destinationUrl];
        try {
            await pool.query(query, values);
        } catch (err) {
            console.error(`  Error migrating affiliate program ID ${program.id}:`, err.message);
        }
    }
    console.log('Affiliate program migration complete.');
}

async function migrateProducts() {
    const data = readJsonFile('products.json');
    if (!data || !data.products) return;
    const products = data.products;
    console.log(`\nMigrating ${products.length} products...`);
    for (const product of products) {
        const query = `INSERT INTO products (id, name, tools, brands, regulations, competitors, uniqueness) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name;`;
        const values = [product.id, product.name, product.tools, product.brands, product.regulations, product.competitors, product.uniqueness];
        try {
            await pool.query(query, values);
        } catch (err) {
            console.error(`  Error migrating product ID ${product.id}:`, err.message);
        }
    }
    console.log('Product migration complete.');
}

async function migrateProfessionals() {
    const insertProfessional = async (item, type) => {
        const query = `INSERT INTO professionals (id, type, name, title, bio, rate, avatar, socials, portfolio, hidden) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id) DO NOTHING;`;
        const rate = item.rate ? parseFloat(item.rate) : 0;
        const values = [item.id, type, item.name, item.title, item.bio, rate, item.avatar, JSON.stringify(item.socials), JSON.stringify(item.portfolio), item.hidden || false];
        try {
            await pool.query(query, values);
        } catch (err) {
            console.error(`  Error migrating ${type} ID ${item.id}:`, err.message);
        }
    };
    const expertsData = readJsonFile('experts.json');
    if (expertsData) {
        const items = Object.values(expertsData);
        console.log(`\nMigrating ${items.length} experts...`);
        for (const item of items) {
            await insertProfessional(item, 'expert');
        }
        console.log('Experts migration complete.');
    }
    const foundersData = readJsonFile('founders.json');
    if (foundersData) {
        const items = Object.values(foundersData);
        console.log(`\nMigrating ${items.length} founders...`);
        for (const item of items) {
            await insertProfessional(item, 'founder');
        }
        console.log('Founders migration complete.');
    }
}


async function migrateEducation() {
    const data = readJsonFile('education-content.json');
    if (!data || !data.categories) return;
    const categories = data.categories;
    console.log(`\nMigrating ${categories.length} education categories...`);
    for (const category of categories) {
        try {
            const categoryResult = await pool.query(`INSERT INTO education_categories (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id;`, [category.name]);
            const categoryId = categoryResult.rows[0].id;
            if (category.content && category.content.length > 0) {
                for (const contentItem of category.content) {
                    const contentQuery = `INSERT INTO education_content (category_id, content_id, title, type, source, author, summary) VALUES ($1, $2, $3, $4, $5, $6, $7);`;
                    const contentValues = [categoryId, contentItem.id, contentItem.title, contentItem.type, contentItem.source, contentItem.author, contentItem.summary];
                    await pool.query(contentQuery, contentValues);
                }
            }
        } catch (err) {
             console.error(`  Error migrating education category ${category.name}:`, err.message);
        }
    }
    console.log('Education content migration complete.');
}

async function migrateReferrals() {
    const data = readJsonFile('referrals.json');
    if(!data) return;
    const referralEntries = Object.entries(data);
    console.log(`\nMigrating ${referralEntries.length} referral program summaries...`);
    for (const [programId, details] of referralEntries) {
        if (details.referrers) {
            for (const [username, count] of Object.entries(details.referrers)) {
                const query = `INSERT INTO referral_summary (program_id, referrer_username, referral_count) VALUES ($1, $2, $3);`;
                const values = [parseInt(programId), username, count];
                try {
                    await pool.query(query, values);
                } catch(err) {
                    console.error(`  Error migrating referral for program ${programId}, user ${username}:`, err.message);
                }
            }
        }
    }
    console.log('Referral migration complete.');
}

async function migrateResponses() {
    const data = readJsonFile('responses.json');
    if(!data) return;
    const responseEntries = Object.entries(data);
    console.log(`\nMigrating ${responseEntries.length} quest responses...`);
    for (const [questId, userResponses] of responseEntries) {
        for (const [username, responses] of Object.entries(userResponses)) {
            const query = `INSERT INTO quest_responses (quest_id, username, responses) VALUES ($1, $2, $3);`;
            const values = [parseInt(questId), username, JSON.stringify(responses)];
             try {
                await pool.query(query, values);
            } catch(err) {
                console.error(`  Error migrating response for quest ${questId}, user ${username}:`, err.message);
            }
        }
    }
    console.log('Response migration complete.');
}


// --- MAIN FUNCTION ---
async function main() {
  console.log('Starting full database migration...');
  const client = await pool.connect();
  try {
    // Run all migration functions in sequence
    await migrateUsers();
    await migrateQuests();
    await migrateAffiliatePrograms();
    await migrateProducts();
    await migrateProfessionals();
    await migrateEducation();
    await migrateReferrals();
    await migrateResponses();

  } catch (err) {
    console.error('\nAn error occurred during migration:', err);
  } finally {
    await client.release();
    await pool.end();
    console.log('\nFull migration script finished.');
  }
}

// Run the main function
main();
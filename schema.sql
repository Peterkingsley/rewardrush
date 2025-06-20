-- Drop existing tables in reverse order of dependency to start fresh
DROP TABLE IF EXISTS
    "user_activity",
    "quest_responses",
    "referral_summary",
    "conversions",
    "affiliate_clicks",
    "bookings",
    "user_quests",
    "quest_questions",
    "education_content",
    "affiliate_programs",
    "products",
    "professionals",
    "education_categories",
    "redeemable_codes",
    "quests",
    "users" CASCADE;

-- Table for Users
CREATE TABLE "users" (
    "id" SERIAL PRIMARY KEY,
    "username" VARCHAR(255) UNIQUE NOT NULL,
    "email" VARCHAR(255) UNIQUE NOT NULL,
    "password_hash" VARCHAR(255) NOT NULL,
    "full_name" VARCHAR(255) NOT NULL, -- Enforced NOT NULL to match /signup validation
    "avatar" TEXT,
    "points" NUMERIC(10, 2) DEFAULT 0.00,
    "blocked" BOOLEAN DEFAULT false,
    "twitter_handle" VARCHAR(255),
    "wallet_address" VARCHAR(255) UNIQUE,
    "referral_code" VARCHAR(255) UNIQUE,
    "reset_password_token" TEXT,
    "reset_password_expires" TIMESTAMPTZ,
    "last_login" TIMESTAMPTZ,
    "login_streak" INTEGER DEFAULT 0,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Table for Quests
CREATE TABLE "quests" (
    "id" SERIAL PRIMARY KEY,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "reward" VARCHAR(255),
    "status" VARCHAR(50) DEFAULT 'Available',
    "start_time" TIMESTAMPTZ,
    "end_time" TIMESTAMPTZ,
    "participants" INTEGER DEFAULT 0,
    "quiz_page" TEXT
);

-- Table for Questions within Quests
CREATE TABLE "quest_questions" (
    "id" SERIAL PRIMARY KEY,
    "quest_id" INTEGER REFERENCES "quests"("id") ON DELETE CASCADE,
    "question_id" VARCHAR(255),
    "question_type" VARCHAR(255),
    "question_text" TEXT,
    "options" JSONB,
    "correct_answer" TEXT
);

-- Table to track user completion of quests
CREATE TABLE "user_quests" (
    "id" SERIAL PRIMARY KEY,
    "user_id" INTEGER REFERENCES "users"("id") ON DELETE CASCADE,
    "quest_id" INTEGER REFERENCES "quests"("id") ON DELETE CASCADE,
    "completed_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE("user_id", "quest_id")
);

-- Table for Affiliate Programs
CREATE TABLE "affiliate_programs" (
    "id" SERIAL PRIMARY KEY,
    "category" VARCHAR(255),
    "title" TEXT,
    "guidelines" TEXT,
    "details" TEXT,
    "pros" TEXT[],
    "cons" TEXT[],
    "payout" VARCHAR(255),
    "destination_url" TEXT
);

-- Table for Products
CREATE TABLE "products" (
    "id" SERIAL PRIMARY KEY,
    "name" TEXT,
    "tools" TEXT,
    "brands" TEXT,
    "regulations" TEXT,
    "competitors" TEXT,
    "uniqueness" TEXT
);

-- Table for Redeemable Codes (used in /withdraw)
CREATE TABLE "redeemable_codes" (
    "id" SERIAL PRIMARY KEY,
    "user_id" INTEGER REFERENCES "users"("id") ON DELETE CASCADE NOT NULL,
    "code" VARCHAR(16) UNIQUE NOT NULL, -- Reduced to VARCHAR(16) for 16-char hex codes
    "amount" NUMERIC(10, 2) NOT NULL,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP, -- Standardized to TIMESTAMPTZ
    "is_used" BOOLEAN DEFAULT FALSE
);

-- Table for Experts and Founders (combined into 'professionals')
CREATE TABLE "professionals" (
    "id" VARCHAR(255) PRIMARY KEY,
    "type" VARCHAR(50) NOT NULL, -- 'expert' or 'founder'
    "name" VARCHAR(255),
    "title" VARCHAR(255),
    "bio" TEXT,
    "rate" NUMERIC,
    "avatar" TEXT,
    "socials" JSONB,
    "portfolio" JSONB,
    "hidden" BOOLEAN DEFAULT false
);

-- Table for Education Categories
CREATE TABLE "education_categories" (
    "id" SERIAL PRIMARY KEY,
    "name" VARCHAR(255) UNIQUE NOT NULL
);

-- Table for Education Content
CREATE TABLE "education_content" (
    "id" SERIAL PRIMARY KEY,
    "category_id" INTEGER REFERENCES "education_categories"("id") ON DELETE CASCADE,
    "content_id" INTEGER,
    "title" TEXT,
    "type" VARCHAR(255),
    "source" TEXT,
    "author" VARCHAR(255),
    "summary" TEXT
);

-- Table for Expert/Founder Bookings
CREATE TABLE "bookings" (
    "id" SERIAL PRIMARY KEY,
    "user_id" INTEGER REFERENCES "users"("id") ON DELETE CASCADE,
    "professional_id" VARCHAR(255) REFERENCES "professionals"("id") ON DELETE CASCADE,
    "reason" TEXT,
    "preferred_date" TEXT,
    "status" VARCHAR(255) DEFAULT 'pending',
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Table for tracking affiliate link clicks
CREATE TABLE "affiliate_clicks" (
    "id" SERIAL PRIMARY KEY,
    "program_id" INTEGER REFERENCES "affiliate_programs"("id"),
    "affiliate_username" VARCHAR(255),
    "ip_address" VARCHAR(255),
    "timestamp" TIMESTAMPTZ DEFAULT NOW()
);

-- Table for tracking conversions from affiliate links
CREATE TABLE "conversions" (
    "id" SERIAL PRIMARY KEY,
    "program_id" INTEGER REFERENCES "affiliate_programs"("id"),
    "affiliate_username" VARCHAR(255),
    "conversion_value" NUMERIC,
    "payout_amount" NUMERIC,
    "timestamp" TIMESTAMPTZ DEFAULT NOW()
);

-- Table for quest responses (retained for future use)
CREATE TABLE "quest_responses" (
    "id" SERIAL PRIMARY KEY,
    "quest_id" INTEGER,
    "username" VARCHAR(255),
    "responses" JSONB
);

-- Table for referral summaries (retained for future use)
CREATE TABLE "referral_summary" (
    "id" SERIAL PRIMARY KEY,
    "program_id" INTEGER,
    "referrer_username" VARCHAR(255),
    "referral_count" INTEGER
);

-- Table for logging user activities
CREATE TABLE "user_activity" (
    "id" SERIAL PRIMARY KEY,
    "user_id" INTEGER REFERENCES "users"("id") ON DELETE CASCADE,
    "activity_type" VARCHAR(255) NOT NULL,
    "details" TEXT,
    "created_at" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Helper function to safely parse payout strings
CREATE OR REPLACE FUNCTION parse_payout(payout_string VARCHAR)
RETURNS NUMERIC AS $$
DECLARE
    match TEXT[];
BEGIN
    -- Handle null or empty input
    IF payout_string IS NULL OR TRIM(payout_string) = '' THEN
        RETURN 0;
    END IF;
    -- Extract numeric value (e.g., '10', '10.50', '$10.50')
    match := regexp_match(payout_string, '\$?(\d+(\.\d+)?)');
    IF match IS NOT NULL THEN
        RETURN match[1]::NUMERIC;
    ELSE
        RETURN 0;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Indexes for better query performance
CREATE INDEX idx_users_username ON "users" ("username");
CREATE INDEX idx_user_quests_user_id ON "user_quests" ("user_id");
CREATE INDEX idx_conversions_affiliate_username ON "conversions" ("affiliate_username");
CREATE INDEX idx_affiliate_clicks_affiliate_username ON "affiliate_clicks" ("affiliate_username");
CREATE INDEX idx_bookings_user_id ON "bookings" ("user_id");
CREATE INDEX idx_user_activity_user_id ON "user_activity" ("user_id");
CREATE INDEX idx_redeemable_codes_user_id ON "redeemable_codes" ("user_id"); -- Added for /redeemable-codes
CREATE INDEX idx_redeemable_codes_is_used ON "redeemable_codes" ("is_used"); -- Added for filtering unused codes
--
-- PostgreSQL database dump
--

-- Dumped from database version 17.5
-- Dumped by pg_dump version 17.5

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: affiliate_clicks; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.affiliate_clicks (
    id integer NOT NULL,
    program_id integer,
    affiliate_username character varying(255),
    ip_address character varying(255),
    "timestamp" timestamp with time zone DEFAULT now()
);


ALTER TABLE public.affiliate_clicks OWNER TO postgres;

--
-- Name: affiliate_clicks_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.affiliate_clicks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.affiliate_clicks_id_seq OWNER TO postgres;

--
-- Name: affiliate_clicks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.affiliate_clicks_id_seq OWNED BY public.affiliate_clicks.id;


--
-- Name: affiliate_programs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.affiliate_programs (
    id integer NOT NULL,
    category character varying(255),
    title text,
    guidelines text,
    details text,
    pros text[],
    cons text[],
    payout character varying(255),
    destination_url text
);


ALTER TABLE public.affiliate_programs OWNER TO postgres;

--
-- Name: bookings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.bookings (
    id integer NOT NULL,
    user_id integer,
    professional_id character varying(255),
    reason text,
    preferred_date text,
    status character varying(255) DEFAULT 'pending'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.bookings OWNER TO postgres;

--
-- Name: bookings_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.bookings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.bookings_id_seq OWNER TO postgres;

--
-- Name: bookings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.bookings_id_seq OWNED BY public.bookings.id;


--
-- Name: conversions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.conversions (
    id integer NOT NULL,
    program_id integer,
    affiliate_username character varying(255),
    conversion_value numeric,
    payout_amount numeric,
    "timestamp" timestamp with time zone DEFAULT now()
);


ALTER TABLE public.conversions OWNER TO postgres;

--
-- Name: conversions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.conversions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.conversions_id_seq OWNER TO postgres;

--
-- Name: conversions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.conversions_id_seq OWNED BY public.conversions.id;


--
-- Name: education_categories; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.education_categories (
    id integer NOT NULL,
    name character varying(255) NOT NULL
);


ALTER TABLE public.education_categories OWNER TO postgres;

--
-- Name: education_categories_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.education_categories_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.education_categories_id_seq OWNER TO postgres;

--
-- Name: education_categories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.education_categories_id_seq OWNED BY public.education_categories.id;


--
-- Name: education_content; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.education_content (
    id integer NOT NULL,
    category_id integer,
    content_id integer,
    title text,
    type character varying(255),
    source text,
    author character varying(255),
    summary text
);


ALTER TABLE public.education_content OWNER TO postgres;

--
-- Name: education_content_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.education_content_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.education_content_id_seq OWNER TO postgres;

--
-- Name: education_content_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.education_content_id_seq OWNED BY public.education_content.id;


--
-- Name: products; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.products (
    id integer NOT NULL,
    name text,
    tools text,
    brands text,
    regulations text,
    competitors text,
    uniqueness text
);


ALTER TABLE public.products OWNER TO postgres;

--
-- Name: professionals; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.professionals (
    id character varying(255) NOT NULL,
    type character varying(50),
    name character varying(255),
    title character varying(255),
    bio text,
    rate numeric,
    avatar text,
    socials jsonb,
    portfolio jsonb,
    hidden boolean
);


ALTER TABLE public.professionals OWNER TO postgres;

--
-- Name: quest_questions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.quest_questions (
    id integer NOT NULL,
    quest_id integer,
    question_id character varying(255),
    question_type character varying(255),
    question_text text,
    options jsonb,
    correct_answer text
);


ALTER TABLE public.quest_questions OWNER TO postgres;

--
-- Name: quest_questions_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.quest_questions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.quest_questions_id_seq OWNER TO postgres;

--
-- Name: quest_questions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.quest_questions_id_seq OWNED BY public.quest_questions.id;


--
-- Name: quests; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.quests (
    id integer NOT NULL,
    title text NOT NULL,
    description text,
    reward character varying(255),
    status character varying(255),
    start_time timestamp with time zone,
    end_time timestamp with time zone,
    participants integer
);


ALTER TABLE public.quests OWNER TO postgres;

--
-- Name: user_quests; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_quests (
    id integer NOT NULL,
    user_id integer,
    quest_id integer,
    completed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.user_quests OWNER TO postgres;

--
-- Name: user_quests_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.user_quests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_quests_id_seq OWNER TO postgres;

--
-- Name: user_quests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.user_quests_id_seq OWNED BY public.user_quests.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    full_name character varying(255),
    avatar text,
    points integer DEFAULT 0,
    blocked boolean DEFAULT false,
    twitter_handle character varying(255),
    wallet_address character varying(255),
    referral_code character varying(255),
    reset_password_token text,
    reset_password_expires timestamp with time zone,
    last_login timestamp with time zone,
    login_streak integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_id_seq OWNER TO postgres;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: affiliate_clicks id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.affiliate_clicks ALTER COLUMN id SET DEFAULT nextval('public.affiliate_clicks_id_seq'::regclass);


--
-- Name: bookings id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.bookings ALTER COLUMN id SET DEFAULT nextval('public.bookings_id_seq'::regclass);


--
-- Name: conversions id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.conversions ALTER COLUMN id SET DEFAULT nextval('public.conversions_id_seq'::regclass);


--
-- Name: education_categories id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.education_categories ALTER COLUMN id SET DEFAULT nextval('public.education_categories_id_seq'::regclass);


--
-- Name: education_content id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.education_content ALTER COLUMN id SET DEFAULT nextval('public.education_content_id_seq'::regclass);


--
-- Name: quest_questions id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.quest_questions ALTER COLUMN id SET DEFAULT nextval('public.quest_questions_id_seq'::regclass);


--
-- Name: user_quests id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_quests ALTER COLUMN id SET DEFAULT nextval('public.user_quests_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Data for Name: affiliate_clicks; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.affiliate_clicks (id, program_id, affiliate_username, ip_address, "timestamp") FROM stdin;
\.


--
-- Data for Name: affiliate_programs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.affiliate_programs (id, category, title, guidelines, details, pros, cons, payout, destination_url) FROM stdin;
1	Sign Up	Binance Signup Campaign	Refer new users to Binance, the world's leading cryptocurrency exchange. Payout is processed after the referred user completes their initial identity verification (KYC). Ensure referrals are from non-restricted countries.	Earn rewards for every new user who signs up on Binance and completes KYC.	{"High conversion rate","Trusted global brand","Quick payout cycle"}	{"KYC process can be a barrier","Geographic restrictions apply"}	$5 per KYC-verified signup	https://www.binance.com/en/register
2	Sign Up	Coinbase New User Bonus	Promote Coinbase to new crypto users. The referred user must sign up and buy or sell at least $100 in crypto within 180 days. You both get a bonus.	You and your referral both get $10 in Bitcoin when they buy or sell $100+ of crypto.	{"Strong incentive for both parties","User-friendly for beginners","Reputable US-based company"}	{"Requires a significant transaction","180-day time limit"}	$10 in BTC	https://www.coinbase.com/signup
3	Sign Up	Metamask Wallet Installs	Get rewarded for driving new installs of the Metamask browser extension. User must install the extension and create a new wallet. Only desktop browser installs are counted.	Promote the most popular self-custody wallet for Ethereum and EVM chains.	{"Essential Web3 tool","Huge potential user base","Simple task for users"}	{"Lower payout per action","Desktop only"}	$1.50 per install & wallet creation	https://metamask.io/download/
4	Sign Up	Ledger Hardware Wallet	Earn a commission on sales of Ledger hardware wallets. Users must purchase a device through your unique link. Payout is a percentage of the total sale value.	Promote the leading hardware wallet for ultimate crypto security.	{"High-ticket item, larger commissions","Strong brand recognition","Appeals to serious investors"}	{"Requires a physical purchase","Longer sales cycle"}	10% of Sale Value	https://www.ledger.com/
5	Sign Up	Earn with ChatGPT Plus	ChatGPT Plus is a subscription by OpenAI offering faster responses and access to the latest models. Every time someone subscribes through your link, you earn a commission. Only valid, unique sign-ups from real users will be counted.	Refer users to ChatGPT Plus using your unique affiliate link.	{"High-converting product","Backed by OpenAI","Monthly recurring potential"}	{"Requires paid subscription for payout","Competitive affiliate space"}	$15/Subscription	https://openai.com/chatgpt/
6	Trading Volume	KuCoin Trading Fee Commission	Commission is based on spot trading fees only. Valid for the first 6 months of the referred user's activity. Great for promoting to active traders.	Earn a percentage of the trading fees for users who sign up and trade on KuCoin.	{"Recurring revenue potential","Popular exchange with many assets","Detailed performance dashboard"}	{"Reliant on user's trading activity","Commission ends after 6 months"}	20% of trading fees	https://www.kucoin.com/ucenter/signup
7	Trading Volume	Bybit Derivatives Trading	Earn commissions from trading fees generated by your referrals on Bybit's derivatives platform. Ideal for communities focused on advanced trading strategies.	Promote one of the largest crypto derivatives exchanges and earn from your network's trades.	{"High volume potential","Tiered commission rates","Lifetime revenue share"}	{"Derivatives trading is high-risk","Appeals to a niche audience"}	Up to 30% of trading fees	https://www.bybit.com/en/sign-up
8	Trading Volume	Gate.io Spot Trading	Refer users to Gate.io and earn a commission on their spot trading activities. Gate.io is known for its vast selection of altcoins, attracting exploratory traders.	Earn a lifetime commission from one of the most diverse crypto exchanges.	{"Lifetime commission","Massive selection of cryptocurrencies","Good for altcoin gem hunters"}	{"Lower volume on some pairs","UI can be complex for new users"}	40% of trading fees	https://www.gate.io/signup
9	Trading Volume	dYdX Decentralized Perpetuals	Promote the leading decentralized derivatives exchange. Earn a percentage of the fees generated by users who trade through your referral link. Requires users to connect their own wallet.	Earn from on-chain trading activity on the dYdX protocol.	{"Promote decentralization (DeFi)","Non-custodial trading","Transparent on-chain activity"}	{"Requires user knowledge of DeFi","Gas fees on Ethereum can be high"}	15% of trading fees	https://dydx.exchange/
10	Trading Volume	MEXC Global Futures	Invite friends to trade futures on MEXC and earn a high commission rate. Known for its user-friendly futures interface and high leverage options.	Earn high rebates from one of the fastest-growing futures exchanges.	{"Very high commission rate","Frequent promotions and bonuses","No KYC required for some features"}	{"High leverage is risky for users","Less regulated than other exchanges"}	Up to 70% of trading fees	https://www.mexc.com/register
11	Video Creation	RewardRush Platform Review	Video must clearly show the platform's features (Quests, Affiliate, Education). Must include your affiliate link in the description. Must have at least 1,000 views to be eligible for the base payout.	Create a video review of the RewardRush platform (min. 2 minutes) and post it on YouTube or TikTok.	{"Creative freedom","High payout potential","Showcase your content creation skills"}	{"Requires video editing skills","View count can be hard to achieve"}	$50 - $500 based on views and quality	https://rewardrush.com
12	Video Creation	Crypto.com App Tutorial	Create a beginner-friendly tutorial on how to use the Crypto.com app. Cover topics like buying crypto, using the crypto card, or earning interest. Video must be over 3 minutes.	Help new users navigate the Crypto.com ecosystem with a helpful video guide.	{"Evergreen content potential","Large and growing user base","Positions you as an expert"}	{"App interface changes frequently","Many tutorials already exist"}	$100 for high-quality, approved videos	https://crypto.com/app
13	Video Creation	Ledger 'How to Secure Your Crypto' Video	Create an educational video about the importance of self-custody and hardware wallets, featuring a Ledger device. The video should not be a direct ad but an educational piece.	Educate the community on crypto security and feature Ledger as the solution.	{"Valuable content for the community","Positions you as a security advocate","Premium brand association"}	{"Requires owning the product to demonstrate","More educational than direct sales"}	$200 per approved video	https://www.ledger.com
14	Video Creation	Create a 'Top 5 Altcoins' Video on MEXC	Research and create a video discussing 5 promising altcoins available on the MEXC exchange. You must disclose your affiliate relationship and include your MEXC referral link.	Create engaging content for the 'gem hunter' community and drive sign-ups to MEXC.	{"High viewer engagement topic","Drives traffic to your referral link","Fun research opportunity"}	{"Requires market knowledge","Highly speculative and risky for viewers"}	$75 + signup commissions	https://www.mexc.com/
15	Video Creation	Unstoppable Domains Web3 Identity Explainer	Create a video explaining what a Web3 domain is and how Unstoppable Domains works. Show the process of claiming a domain. Must be clear, concise, and professional.	Explain the future of digital identity and promote Unstoppable Domains.	{"Future-focused topic","Simple concept to explain visually","One-time purchase, no renewals"}	{"Concept might be new to many","Less immediate use case for some viewers"}	$50 per approved video	https://unstoppabledomains.com/
16	Post on Socials	Tweet about a RewardRush Quest	Post a Tweet (X) about a specific, currently active quest on RewardRush. You must tag @RewardRushApp (hypothetical) and use the hashtag #RewardRush. The tweet must include a screenshot of the quest.	Share your experience with our quests on Twitter and earn a small reward.	{"Quick and easy to complete","Engages your existing audience","Low barrier to entry"}	{"Low payout","Requires an active Twitter account"}	$2 per valid Tweet	https://twitter.com
17	Post on Socials	Share Your Crypto.com Card	Post a creative picture or story on Instagram featuring your Crypto.com Visa card. You must tag @cryptocom and include your referral code in the post description.	Show off your metal crypto card on Instagram and earn CRO.	{"Fun and visual task","High potential for engagement","Leverages a physical product"}	{"Requires owning the card","Publicly sharing financial-related info"}	$10 in CRO	https://www.instagram.com
18	Post on Socials	Promote a CoinMarketCap Airdrop	Find an active airdrop on CoinMarketCap and share it on Facebook or Reddit. Your post must explain what the project is and how to participate via your affiliate link.	Help your community find new crypto airdrops and earn for sharing.	{"Provides value to your followers","Leverages existing platform features","Drives clicks and signups"}	{"Airdrops are often low value","High competition"}	$5 per 100 clicks	https://coinmarketcap.com/airdrop/
19	Post on Socials	LinkedIn Post about Web3 Careers	Write a thoughtful post on LinkedIn (at least 100 words) about the future of careers in Web3. Mention RewardRush as a platform for getting started and include a link to our 'Education' page.	Share insights on LinkedIn and position RewardRush as a key educational resource.	{"Targets a professional audience","Builds your personal brand","High-quality lead generation"}	{"Requires professional writing skills","LinkedIn algorithm can be tricky"}	$25 per post with 50+ reactions	https://www.linkedin.com
20	Post on Socials	Create a Reddit Thread on r/CryptoCurrency	Start a discussion thread in the r/CryptoCurrency subreddit about the easiest ways for beginners to earn their first crypto. You must organically mention RewardRush and your affiliate link in a comment, not the main post, to avoid being marked as spam.	Engage with the largest crypto community on Reddit.	{"Massive audience reach","High potential for organic discussion","Credible platform"}	{"High risk of being removed by moderators","Requires careful, non-spammy posting"}	$50 for a thread with 100+ upvotes	https://www.reddit.com/r/CryptoCurrency/
21	Transacting Users	Ramp Network First Transaction	Refer users to Ramp, a simple fiat-to-crypto onramp. You earn a reward after your referred user makes their first crypto purchase of at least $50.	Help users buy their first crypto easily with a credit card or bank transfer.	{"Very simple user experience","Solves a common beginner problem","Integrates with many dApps"}	{"Transaction fees can be high","ID verification required"}	$10 per first transaction	https://ramp.network/
22	Transacting Users	MoonPay Crypto Purchase	Earn a commission when your referred users buy crypto using MoonPay. Payout is a percentage of the total transaction volume for the first 90 days.	Promote a leading payment infrastructure for crypto.	{"Recurring commission for 90 days","Supports many currencies and payment methods","Widely integrated service"}	{"Commission is small per transaction","Requires consistent volume"}	0.5% of transaction volume	https://www.moonpay.com/buy
23	Transacting Users	Uniswap First Swap	Guide a new user to perform their first token swap on the Uniswap protocol. This is a technical task that requires a user to have a wallet and ETH for gas.	Introduce users to the world of decentralized exchanges (DEXs).	{"Teaches a core DeFi skill","Empowers users with self-custody","High educational value"}	{"Complex for absolute beginners","Gas fees can be a deterrent"}	$15 per first swap	https://app.uniswap.org/
24	Transacting Users	Crypto.com App Card Top-Up	Reward is paid when a user you referred tops up their Crypto.com Visa Card with at least $100 for the first time.	Encourage users to start using their crypto for real-world purchases.	{"Promotes real-world utility","Encourages platform lock-in","Simple action for existing cardholders"}	{"Requires user to have staked for the card","Not available in all regions"}	$5 in CRO	https://crypto.com/cards
25	Transacting Users	Aave Deposit	Refer a user who makes their first deposit of at least $200 worth of assets into the Aave lending protocol. The deposit must be held for a minimum of 7 days.	Introduce users to decentralized lending and borrowing.	{"Showcases a blue-chip DeFi protocol","High value action","Teaches users about yield farming"}	{"Requires significant capital","Users must understand smart contract risk"}	$25 per qualifying deposit	https://aave.com/
26	Pay for a Product	Purchase an Unstoppable Domain	Earn a commission when a user buys a .crypto, .x, or .nft domain through your link. No renewal fees make this an easy sell for long-term holders.	Help users get their first decentralized, human-readable crypto address.	{"One-time purchase model","High relevance in the NFT space","Practical use case"}	{"Domain utility is still developing","Less known than traditional domains"}	20% of sale price	https://unstoppabledomains.com/
27	Pay for a Product	CoinLedger Tax Software	Refer users to the CoinLedger crypto tax software. You earn a commission when they purchase a paid plan to generate their tax reports.	Help crypto traders and investors solve their biggest headache: taxes.	{"Solves a major pain point","High demand during tax season","Recurring annual purchase potential"}	{"Seasonal demand","Users may be reluctant to pay for tax software"}	25% of plan price	https://coinledger.io/
28	Pay for a Product	Subscribe to The Defiant	Refer users to a paid subscription for The Defiant, a leading DeFi news and research platform. You earn a recurring commission for as long as they stay subscribed.	Promote high-quality, independent crypto journalism and research.	{"Highly respected publication","Recurring revenue","Targets an informed audience"}	{"High subscription cost can be a barrier","Niche B2B/Prosumer audience"}	30% recurring commission	https://thedefiant.io/
29	Pay for a Product	3Commas Trading Bot Subscription	Earn a commission when your referrals subscribe to a paid plan on 3Commas, an automated crypto trading bot platform.	Introduce active traders to the power of automated trading strategies.	{"Targets active, high-volume traders","Recurring subscription model","Strong community and support"}	{"Complex product for beginners","Trading bots carry inherent risks"}	25% recurring commission	https://3commas.io/
30	Pay for a Product	NordVPN Crypto Payment	Earn a commission when a new user purchases a NordVPN plan and pays using cryptocurrency. NordVPN is a top-tier VPN service that accepts Bitcoin and other crypto.	Promote online privacy and security to the crypto community.	{"High brand recognition outside crypto","Strong privacy use case","Excellent affiliate support"}	{"Many competing VPN services","Payout only for crypto payments"}	40% of 1-year plan purchase	https://nordvpn.com/features/buy-vpn-with-crypto/
\.


--
-- Data for Name: bookings; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.bookings (id, user_id, professional_id, reason, preferred_date, status, created_at) FROM stdin;
\.


--
-- Data for Name: conversions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.conversions (id, program_id, affiliate_username, conversion_value, payout_amount, "timestamp") FROM stdin;
\.


--
-- Data for Name: education_categories; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.education_categories (id, name) FROM stdin;
1	Graphic Design
2	Community Management
3	Social Media Management
4	Digital Marketing
5	Business Development
6	Frontend Development
7	Backend Development
8	Full Stack Engineer
\.


--
-- Data for Name: education_content; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.education_content (id, category_id, content_id, title, type, source, author, summary) FROM stdin;
1	1	1	Intro to Graphic Design	Video	https://www.youtube.com/embed/ZQ6sE2oX8fk	Unknown	A video introducing the basics of graphic design.
2	1	2	Graphic Design School	Article	https://www.amazon.com/Graphic-Design-School-Fundamentals-Applications/dp/1119342711	Unknown	A comprehensive book on graphic design fundamentals.
3	1	3	Learn from Sascha Huber	Article	https://www.behance.net/saschahuber	Sascha Huber	Explore the portfolio and insights of designer Sascha Huber.
4	1	4	Book a Consultation with an Expert	Consultation	consultation://graphic-design	RewardRush Experts	Schedule a personalized consultation with a graphic design expert.
5	2	1	Community Building	Video	https://www.youtube.com/embed/kjF-0xCPoQ0	Unknown	A video on strategies for building online communities.
6	2	2	Community Management Handbook	Article	https://www.amazon.com/Community-Management-Best-Practices-Handbook/dp/1502412345	Unknown	A handbook outlining best practices for community management.
7	2	3	Learn from Julien Codorniou	Article	https://twitter.com/julien	Julien Codorniou	Insights from community management expert Julien Codorniou.
8	2	4	Book a Consultation with an Expert	Consultation	consultation://community-management	RewardRush Experts	Schedule a personalized consultation with a community management expert.
9	3	1	Social Media Strategies	Video	https://www.youtube.com/embed/9bZkp7q19f0	Unknown	A video on effective social media strategies.
10	3	2	Social Media Marketing Workbook	Article	https://www.amazon.com/Social-Media-Marketing-Workbook-2023/dp/173622904X	Unknown	A workbook for mastering social media marketing.
11	3	3	Learn from Gary Vaynerchuk	Article	https://twitter.com/garyvee	Gary Vaynerchuk	Insights from social media expert Gary Vaynerchuk.
12	3	4	Book a Consultation with an Expert	Consultation	consultation://social-media-management	RewardRush Experts	Schedule a personalized consultation with a social media management expert.
13	4	1	Digital Campaigns	Video	https://www.youtube.com/embed/6mhrXh8Z0kA	Unknown	A video on creating effective digital marketing campaigns.
14	4	2	Digital Marketing Strategy	Article	https://www.amazon.com/Digital-Marketing-Strategy-Implementation-Distribution/dp/0749474718	Unknown	A book on digital marketing strategies and implementation.
15	4	3	Learn from Neil Patel	Article	https://twitter.com/neilpatel	Neil Patel	Insights from digital marketing expert Neil Patel.
16	4	4	Book a Consultation with an Expert	Consultation	consultation://digital-marketing	RewardRush Experts	Schedule a personalized consultation with a digital marketing expert.
17	5	1	Business Growth	Video	https://www.youtube.com/embed/T5pH2hC2b-4	Unknown	A video on strategies for business growth.
18	5	2	Business Development Playbook	Article	https://www.amazon.com/Business-Development-Playbook-Strategies-Scaling/dp/1734629619	Unknown	A playbook for business development and scaling strategies.
19	5	3	Learn from Mark Cuban	Article	https://twitter.com/markcuban	Mark Cuban	Insights from business development expert Mark Cuban.
20	5	4	Book a Consultation with an Expert	Consultation	consultation://business-development	RewardRush Experts	Schedule a personalized consultation with a business development expert.
21	6	1	Frontend Basics	Video	https://www.youtube.com/embed/FM8f_uH1r5s	Unknown	A video covering the basics of frontend development.
22	6	2	Eloquent JavaScript	Article	https://www.amazon.com/Eloquent-JavaScript-3rd-Introduction-Programming/dp/1593279507	Unknown	A book on JavaScript programming for frontend developers.
23	6	3	Learn from Wes Bos	Article	https://twitter.com/wesbos	Wes Bos	Insights from frontend development expert Wes Bos.
24	6	4	Book a Consultation with an Expert	Consultation	consultation://frontend-development	RewardRush Experts	Schedule a personalized consultation with a frontend development expert.
25	7	1	Backend Essentials	Video	https://www.youtube.com/embed/2y8x3z5bA5U	Unknown	A video on essential backend development concepts.
26	7	2	Node.js Design Patterns	Article	https://www.amazon.com/Node-js-Design-Patterns-Real-World/dp/1839214112	Unknown	A book on design patterns for Node.js backend development.
27	7	3	Learn from Addy Osmani	Article	https://twitter.com/addyosmani	Addy Osmani	Insights from backend development expert Addy Osmani.
28	7	4	Book a Consultation with an Expert	Consultation	consultation://backend-development	RewardRush Experts	Schedule a personalized consultation with a backend development expert.
29	8	1	Full Stack Overview	Video	https://www.youtube.com/embed/WK4m2hC2b-4	Unknown	A video providing an overview of full stack development.
30	8	2	Full Stack Development with React & Node	Article	https://www.amazon.com/Full-Stack-Development-React-Node/dp/180323316X	Unknown	A book on full stack development using React and Node.
31	8	3	Learn from Brad Traversy	Article	https://twitter.com/bradtraversy	Brad Traversy	Insights from full stack development expert Brad Traversy.
32	8	4	Book a Consultation with an Expert	Consultation	consultation://full-stack-engineer	RewardRush Experts	Schedule a personalized consultation with a full stack engineering expert.
\.


--
-- Data for Name: products; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.products (id, name, tools, brands, regulations, competitors, uniqueness) FROM stdin;
1	Launching an Onramp Brand (e.g., OnRamp)	Ramp Instant SDK, Swapple white-label solution	Ramp Network, Swapple Onramp (150+ countries, 110+ assets), Onramp.us (B2B onboarding focus)	Secure KYC/AML compliance, fiat-crypto integration, 24/7 support	Swapple, Onramp Funds	Focus on seamless B2B onboarding and extensive asset support
2	Building a Mobile Game (e.g., Blacktop Hoops)	Unity, Unreal Engine, Chartboost Mediation (ad monetization), GameAnalytics (metrics)	Chartboost, GameAnalytics	Engaging gameplay, scalable servers, user acquisition strategy (CPIs)	Cursed Crown, Toy Blast, Dreamdale	Focus on immersive sports gameplay with advanced analytics
3	Setting Up a Crypto Exchange (e.g., Binance)	Unicsoft (blockchain/NFT integration), Ramp Network (on/off-ramp)	Chainalysis (compliance), Circle (USDC stablecoin)	Regulatory licenses (e.g., NYDFS BitLicense), cold storage, high liquidity	Kraken, Coinbase	Integration of blockchain and NFT features with robust compliance
4	Launching an Onramp Brand (e.g., Swapple)	White-label payment solution, Snov.io (lead gen)	Swapple Onramp (500M+ users), Ramp Network	One-click payment integration, fraud prevention	OnRamp, Onramp Funds	Massive user base with streamlined payment integration
5	Building a Mobile Game (e.g., Cursed Crown)	CoreX3D (browser-based), Machinations.io (economy design)	Glade (AI worlds)	AI-driven narrative, multiplayer infrastructure	Blacktop Hoops, Toy Blast, Dreamdale	AI-driven narrative and multiplayer focus in a browser-based game
6	Setting Up a Crypto Exchange (e.g., Kraken)	Bitfinex API, Unicsoft (exchange infrastructure)	Deloitte (auditing), Binance Cloud	2FA security, insurance funds, AML compliance	Binance, Coinbase	Emphasis on security and auditing with Deloitte partnership
7	Launching an Onramp Brand (e.g., Onramp Funds)	Insightly CRM, no-code workflows	Onramp Funds (eCommerce funding)	Fast funding (24h), revenue-based repayment	OnRamp, Swapple	Quick funding solutions tailored for eCommerce
8	Building a Mobile Game (e.g., Toy Blast)	AppLovin (ad tools), Unity	Peak Games (development), Sensor Tower (analytics)	Viral loop, regular content updates	Blacktop Hoops, Cursed Crown, Dreamdale	Viral mechanics with frequent updates to maintain user engagement
9	Setting Up a Crypto Exchange (e.g., Coinbase)	Circle API (stablecoins), Unicsoft (smart contracts)	Onramp (talent), Chainalysis (monitoring)	FDIC insurance, API security, scalability	Binance, Kraken	Focus on regulatory compliance with FDIC insurance
10	Building a Mobile Game (e.g., Dreamdale)	Unity, Machinations.io (flowcharts)	Wiserax (economy design), Chartboost	Balanced economy, event-driven content	Blacktop Hoops, Cursed Crown, Toy Blast	Balanced economy with event-driven content to enhance player retention
\.


--
-- Data for Name: professionals; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.professionals (id, type, name, title, bio, rate, avatar, socials, portfolio, hidden) FROM stdin;
\.


--
-- Data for Name: quest_questions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.quest_questions (id, quest_id, question_id, question_type, question_text, options, correct_answer) FROM stdin;
1	1	q1	multiple-choice	What’s the daily trading volume of Bitcoin?	["$10 billion", "$20 billion", "$30 billion", "$40 billion"]	$30 billion
2	1	q2	open-ended	Who founded Ethereum?	\N	\N
3	2	q1	multiple-choice	What’s the best gaming mouse of 2025?	["Logitech G Pro", "Razer DeathAdder", "SteelSeries Rival", "Corsair Dark Core"]	Logitech G Pro
4	2	q2	open-ended	Which brand sponsors eSports the most?	\N	\N
5	3	q1	multiple-choice	What does KYC stand for?	["Know Your Customer", "Keep Your Cash", "Know Your Credit", "Key Yield Control"]	Know Your Customer
6	3	q2	open-ended	Name a leading fintech app.	\N	\N
7	4	q1	multiple-choice	What’s a smart contract?	["Self-executing contract", "Paper contract", "Manual agreement", "Verbal promise"]	Self-executing contract
8	4	q2	open-ended	What’s the main benefit of decentralization?	\N	\N
9	5	q1	multiple-choice	Which game has the biggest eSports prize pool?	["Dota 2", "Fortnite", "CS:GO", "League of Legends"]	Dota 2
10	5	q2	open-ended	Name a top eSports team.	\N	\N
11	6	q1	multiple-choice	What does NFT stand for?	["Non-Fungible Token", "New Financial Tool", "Network File Transfer", "Non-Fixed Transaction"]	Non-Fungible Token
12	6	q2	open-ended	What’s the most expensive NFT sold?	\N	\N
13	7	q1	multiple-choice	What’s a liquidity pool?	["Shared fund for trading", "Private savings account", "Centralized bank reserve", "Fixed deposit"]	Shared fund for trading
14	7	q2	open-ended	Name a popular DeFi platform.	\N	\N
15	8	q1	multiple-choice	What’s the top mobile game of 2025?	["Genshin Impact", "Call of Duty Mobile", "PUBG Mobile", "Among Us"]	Genshin Impact
16	8	q2	open-ended	Which engine powers most mobile games?	\N	\N
17	9	q1	multiple-choice	What’s a hardware wallet?	["Physical crypto storage", "Online wallet app", "Paper wallet", "Exchange account"]	Physical crypto storage
18	9	q2	open-ended	Name a popular crypto wallet app.	\N	\N
19	10	q1	multiple-choice	What’s the best VR headset of 2025?	["Meta Quest 3", "Valve Index", "PSVR 2", "HTC Vive Pro"]	Meta Quest 3
20	10	q2	open-ended	Which game popularized VR gaming?	\N	\N
\.


--
-- Data for Name: quests; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.quests (id, title, description, reward, status, start_time, end_time, participants) FROM stdin;
1	Crypto Trivia Challenge	Test your knowledge on cryptocurrency basics and win USDT!	50 USDT	Available	2025-05-10 10:00:00+01	2030-01-01 00:59:59+01	120
2	Gaming Gear Quiz	Answer questions about the latest gaming gear and earn USDC!	30 USDC	Available	2025-05-13 09:00:00+01	2030-01-01 00:59:59+01	80
3	Fintech Facts	Learn about fintech innovations through this quiz.	40 points	Available	2025-05-19 10:00:00+01	2025-05-20 13:00:00+01	15
4	Blockchain Basics	A beginner’s quiz on blockchain technology.	60 points	Available	2025-05-17 09:00:00+01	2030-01-01 00:59:59+01	200
5	eSports Trivia	Show off your eSports knowledge and win big!	70 points	Available	2025-05-16 11:00:00+01	2030-01-01 00:59:59+01	150
6	NFT Knowledge	Dive into the world of NFTs with this quiz.	55 points	Available	2025-05-15 13:00:00+01	2030-01-01 00:59:59+01	90
7	DeFi Deep Dive	Explore decentralized finance through this quiz.	65 points	Coming Soon	2025-05-20 10:00:00+01	2025-05-30 15:00:00+01	0
8	Mobile Gaming Trends	Test your knowledge on mobile gaming trends.	45 points	Available	2025-05-17 08:00:00+01	2030-01-01 00:59:59+01	110
9	Crypto Wallet Quiz	Learn about crypto wallets and earn rewards.	50 points	Available	2025-05-18 01:00:00+01	2030-01-01 00:59:59+01	130
10	VR Gaming Challenge	A quiz on the latest VR gaming trends.	80 points	Available	2025-05-16 12:00:00+01	2030-01-01 00:59:59+01	170
\.


--
-- Data for Name: user_quests; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.user_quests (id, user_id, quest_id, completed_at) FROM stdin;
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.users (id, username, email, password_hash, full_name, avatar, points, blocked, twitter_handle, wallet_address, referral_code, reset_password_token, reset_password_expires, last_login, login_streak, created_at) FROM stdin;
1	Royalnoble	peterkingslayer098@gmail.com	$2b$10$4bKKSOe5SXFtjfYsF3qqYeVMpsQqXElrCXiVg5wrCFgrXECC3i2cS	\N	\N	70	f	\N	\N	\N	\N	\N	\N	0	2025-06-18 01:59:41.07094+01
2	eshiet	thecircumfriends@gmail.com	$2b$10$ee/Z7CjS1W9cXIDXDpQO7O1ICdljIEp.OFENlpWqMGQuSTNtwNpyG	\N	\N	0	f	\N	\N	\N	\N	\N	2025-06-18 02:00:22.797309+01	1	2025-06-18 01:59:41.550402+01
\.


--
-- Name: affiliate_clicks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.affiliate_clicks_id_seq', 1, false);


--
-- Name: bookings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.bookings_id_seq', 1, false);


--
-- Name: conversions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.conversions_id_seq', 1, false);


--
-- Name: education_categories_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.education_categories_id_seq', 8, true);


--
-- Name: education_content_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.education_content_id_seq', 32, true);


--
-- Name: quest_questions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.quest_questions_id_seq', 20, true);


--
-- Name: user_quests_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.user_quests_id_seq', 1, false);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.users_id_seq', 2, true);


--
-- Name: affiliate_clicks affiliate_clicks_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.affiliate_clicks
    ADD CONSTRAINT affiliate_clicks_pkey PRIMARY KEY (id);


--
-- Name: affiliate_programs affiliate_programs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.affiliate_programs
    ADD CONSTRAINT affiliate_programs_pkey PRIMARY KEY (id);


--
-- Name: bookings bookings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.bookings
    ADD CONSTRAINT bookings_pkey PRIMARY KEY (id);


--
-- Name: conversions conversions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.conversions
    ADD CONSTRAINT conversions_pkey PRIMARY KEY (id);


--
-- Name: education_categories education_categories_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.education_categories
    ADD CONSTRAINT education_categories_name_key UNIQUE (name);


--
-- Name: education_categories education_categories_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.education_categories
    ADD CONSTRAINT education_categories_pkey PRIMARY KEY (id);


--
-- Name: education_content education_content_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.education_content
    ADD CONSTRAINT education_content_pkey PRIMARY KEY (id);


--
-- Name: products products_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id);


--
-- Name: professionals professionals_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.professionals
    ADD CONSTRAINT professionals_pkey PRIMARY KEY (id);


--
-- Name: quest_questions quest_questions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.quest_questions
    ADD CONSTRAINT quest_questions_pkey PRIMARY KEY (id);


--
-- Name: quests quests_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.quests
    ADD CONSTRAINT quests_pkey PRIMARY KEY (id);


--
-- Name: user_quests user_quests_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_quests
    ADD CONSTRAINT user_quests_pkey PRIMARY KEY (id);


--
-- Name: user_quests user_quests_user_id_quest_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_quests
    ADD CONSTRAINT user_quests_user_id_quest_id_key UNIQUE (user_id, quest_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_referral_code_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_referral_code_key UNIQUE (referral_code);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: users users_wallet_address_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_wallet_address_key UNIQUE (wallet_address);


--
-- Name: affiliate_clicks affiliate_clicks_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.affiliate_clicks
    ADD CONSTRAINT affiliate_clicks_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.affiliate_programs(id);


--
-- Name: bookings bookings_professional_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.bookings
    ADD CONSTRAINT bookings_professional_id_fkey FOREIGN KEY (professional_id) REFERENCES public.professionals(id) ON DELETE CASCADE;


--
-- Name: bookings bookings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.bookings
    ADD CONSTRAINT bookings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: conversions conversions_program_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.conversions
    ADD CONSTRAINT conversions_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.affiliate_programs(id);


--
-- Name: education_content education_content_category_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.education_content
    ADD CONSTRAINT education_content_category_id_fkey FOREIGN KEY (category_id) REFERENCES public.education_categories(id) ON DELETE CASCADE;


--
-- Name: quest_questions quest_questions_quest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.quest_questions
    ADD CONSTRAINT quest_questions_quest_id_fkey FOREIGN KEY (quest_id) REFERENCES public.quests(id) ON DELETE CASCADE;


--
-- Name: user_quests user_quests_quest_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_quests
    ADD CONSTRAINT user_quests_quest_id_fkey FOREIGN KEY (quest_id) REFERENCES public.quests(id) ON DELETE CASCADE;


--
-- Name: user_quests user_quests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_quests
    ADD CONSTRAINT user_quests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


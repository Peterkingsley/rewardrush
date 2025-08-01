PGDMP      8                }         
   rewardrush    16.9 (Debian 16.9-1.pgdg120+1)    17.5 (   �           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                           false            �           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                           false            �           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                           false            �           1262    16389 
   rewardrush    DATABASE     u   CREATE DATABASE rewardrush WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'en_US.UTF8';
    DROP DATABASE rewardrush;
                     rewardrush_user    false            �           0    0 
   rewardrush    DATABASE PROPERTIES     3   ALTER DATABASE rewardrush SET "TimeZone" TO 'utc';
                          rewardrush_user    false                        2615    2200    public    SCHEMA     2   -- *not* creating schema, since initdb creates it
 2   -- *not* dropping schema, since initdb creates it
                     rewardrush_user    false            #           1255    17204    parse_payout(character varying)    FUNCTION       CREATE FUNCTION public.parse_payout(payout_string character varying) RETURNS numeric
    LANGUAGE plpgsql
    AS $_$
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
$_$;
 D   DROP FUNCTION public.parse_payout(payout_string character varying);
       public               rewardrush_user    false    5            �            1259    17144    affiliate_clicks    TABLE     �   CREATE TABLE public.affiliate_clicks (
    id integer NOT NULL,
    program_id integer,
    affiliate_username character varying(255),
    ip_address character varying(255),
    "timestamp" timestamp with time zone DEFAULT now()
);
 $   DROP TABLE public.affiliate_clicks;
       public         heap r       rewardrush_user    false    5            �            1259    17143    affiliate_clicks_id_seq    SEQUENCE     �   CREATE SEQUENCE public.affiliate_clicks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.affiliate_clicks_id_seq;
       public               rewardrush_user    false    233    5            �           0    0    affiliate_clicks_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.affiliate_clicks_id_seq OWNED BY public.affiliate_clicks.id;
          public               rewardrush_user    false    232            �            1259    17058    affiliate_programs    TABLE     �  CREATE TABLE public.affiliate_programs (
    id integer NOT NULL,
    category character varying(255),
    title text,
    guidelines text,
    details text,
    pros text[],
    cons text[],
    payout character varying(255),
    destination_url text,
    brand_website text,
    social_links jsonb,
    brand_dashboard_url text,
    max_participants integer,
    status character varying(50) DEFAULT 'Active'::character varying
);
 &   DROP TABLE public.affiliate_programs;
       public         heap r       rewardrush_user    false    5            �            1259    17057    affiliate_programs_id_seq    SEQUENCE     �   CREATE SEQUENCE public.affiliate_programs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.affiliate_programs_id_seq;
       public               rewardrush_user    false    224    5            �           0    0    affiliate_programs_id_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.affiliate_programs_id_seq OWNED BY public.affiliate_programs.id;
          public               rewardrush_user    false    223            �            1259    17123    bookings    TABLE     0  CREATE TABLE public.bookings (
    id integer NOT NULL,
    user_id integer,
    professional_id character varying(255),
    reason text,
    preferred_date text,
    status character varying(255) DEFAULT 'pending'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.bookings;
       public         heap r       rewardrush_user    false    5            �            1259    17122    bookings_id_seq    SEQUENCE     �   CREATE SEQUENCE public.bookings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.bookings_id_seq;
       public               rewardrush_user    false    231    5            �           0    0    bookings_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.bookings_id_seq OWNED BY public.bookings.id;
          public               rewardrush_user    false    230            �            1259    17159    conversions    TABLE     �   CREATE TABLE public.conversions (
    id integer NOT NULL,
    program_id integer,
    affiliate_username character varying(255),
    conversion_value numeric,
    payout_amount numeric,
    "timestamp" timestamp with time zone DEFAULT now()
);
    DROP TABLE public.conversions;
       public         heap r       rewardrush_user    false    5            �            1259    17158    conversions_id_seq    SEQUENCE     �   CREATE SEQUENCE public.conversions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.conversions_id_seq;
       public               rewardrush_user    false    5    235            �           0    0    conversions_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.conversions_id_seq OWNED BY public.conversions.id;
          public               rewardrush_user    false    234            �            1259    17100    education_categories    TABLE     p   CREATE TABLE public.education_categories (
    id integer NOT NULL,
    name character varying(255) NOT NULL
);
 (   DROP TABLE public.education_categories;
       public         heap r       rewardrush_user    false    5            �            1259    17099    education_categories_id_seq    SEQUENCE     �   CREATE SEQUENCE public.education_categories_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 2   DROP SEQUENCE public.education_categories_id_seq;
       public               rewardrush_user    false    5    227            �           0    0    education_categories_id_seq    SEQUENCE OWNED BY     [   ALTER SEQUENCE public.education_categories_id_seq OWNED BY public.education_categories.id;
          public               rewardrush_user    false    226            �            1259    17109    education_content    TABLE     �   CREATE TABLE public.education_content (
    id integer NOT NULL,
    category_id integer,
    content_id integer,
    title text,
    type character varying(255),
    source text,
    author character varying(255),
    summary text
);
 %   DROP TABLE public.education_content;
       public         heap r       rewardrush_user    false    5            �            1259    17108    education_content_id_seq    SEQUENCE     �   CREATE SEQUENCE public.education_content_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 /   DROP SEQUENCE public.education_content_id_seq;
       public               rewardrush_user    false    229    5            �           0    0    education_content_id_seq    SEQUENCE OWNED BY     U   ALTER SEQUENCE public.education_content_id_seq OWNED BY public.education_content.id;
          public               rewardrush_user    false    228            �            1259    18302    education_experts    TABLE     �   CREATE TABLE public.education_experts (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    title character varying(255),
    avatar character varying(255),
    bio text,
    socials jsonb,
    portfolio jsonb
);
 %   DROP TABLE public.education_experts;
       public         heap r       rewardrush_user    false    5            �            1259    18274    education_materials    TABLE     �   CREATE TABLE public.education_materials (
    id integer NOT NULL,
    skill_id character varying(50),
    title character varying(255) NOT NULL,
    type character varying(50),
    duration character varying(50),
    link character varying(255)
);
 '   DROP TABLE public.education_materials;
       public         heap r       rewardrush_user    false    5            �            1259    18267    education_skills    TABLE     �   CREATE TABLE public.education_skills (
    id character varying(50) NOT NULL,
    title character varying(255) NOT NULL,
    icon character varying(100),
    color character varying(50),
    courses integer,
    hours integer,
    description text
);
 $   DROP TABLE public.education_skills;
       public         heap r       rewardrush_user    false    5            �            1259    17465    experts    TABLE     �   CREATE TABLE public.experts (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    title character varying(255),
    avatar character varying(255),
    color character varying(50)
);
    DROP TABLE public.experts;
       public         heap r       rewardrush_user    false    5                       1259    18614    job_completions    TABLE     �   CREATE TABLE public.job_completions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    program_id integer NOT NULL,
    reward_amount numeric(10,2) NOT NULL,
    completed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
 #   DROP TABLE public.job_completions;
       public         heap r       rewardrush_user    false    5                       1259    18613    job_completions_id_seq    SEQUENCE     �   CREATE SEQUENCE public.job_completions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE public.job_completions_id_seq;
       public               rewardrush_user    false    5    273            �           0    0    job_completions_id_seq    SEQUENCE OWNED BY     Q   ALTER SEQUENCE public.job_completions_id_seq OWNED BY public.job_completions.id;
          public               rewardrush_user    false    272                       1259    18655    job_earnings    TABLE     1  CREATE TABLE public.job_earnings (
    id integer NOT NULL,
    user_id integer NOT NULL,
    program_id integer NOT NULL,
    user_job_id integer,
    amount numeric(10,2) NOT NULL,
    is_final_payment boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
     DROP TABLE public.job_earnings;
       public         heap r       rewardrush_user    false    5                       1259    18654    job_earnings_id_seq    SEQUENCE     �   CREATE SEQUENCE public.job_earnings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE public.job_earnings_id_seq;
       public               rewardrush_user    false    5    275            �           0    0    job_earnings_id_seq    SEQUENCE OWNED BY     K   ALTER SEQUENCE public.job_earnings_id_seq OWNED BY public.job_earnings.id;
          public               rewardrush_user    false    274                       1259    18679    notifications    TABLE     �   CREATE TABLE public.notifications (
    id integer NOT NULL,
    user_id integer NOT NULL,
    message text NOT NULL,
    is_read boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
 !   DROP TABLE public.notifications;
       public         heap r       rewardrush_user    false    5                       1259    18678    notifications_id_seq    SEQUENCE     �   CREATE SEQUENCE public.notifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 +   DROP SEQUENCE public.notifications_id_seq;
       public               rewardrush_user    false    277    5            �           0    0    notifications_id_seq    SEQUENCE OWNED BY     M   ALTER SEQUENCE public.notifications_id_seq OWNED BY public.notifications.id;
          public               rewardrush_user    false    276            �            1259    17495    product_expert_map    TABLE     z   CREATE TABLE public.product_expert_map (
    product_id character varying(50) NOT NULL,
    expert_id integer NOT NULL
);
 &   DROP TABLE public.product_expert_map;
       public         heap r       rewardrush_user    false    5            �            1259    17480    product_tabs    TABLE     �   CREATE TABLE public.product_tabs (
    id integer NOT NULL,
    product_id character varying(50) NOT NULL,
    tab_key character varying(50) NOT NULL,
    title character varying(255),
    icon character varying(100)
);
     DROP TABLE public.product_tabs;
       public         heap r       rewardrush_user    false    5            �            1259    17479    product_tabs_id_seq    SEQUENCE     �   CREATE SEQUENCE public.product_tabs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE public.product_tabs_id_seq;
       public               rewardrush_user    false    245    5            �           0    0    product_tabs_id_seq    SEQUENCE OWNED BY     K   ALTER SEQUENCE public.product_tabs_id_seq OWNED BY public.product_tabs.id;
          public               rewardrush_user    false    244            �            1259    17472    products    TABLE       CREATE TABLE public.products (
    id character varying(50) NOT NULL,
    title character varying(255) NOT NULL,
    icon character varying(100),
    color character varying(50),
    description text,
    guide_title character varying(255),
    guide_description text
);
    DROP TABLE public.products;
       public         heap r       rewardrush_user    false    5            �            1259    17091    professionals    TABLE     5  CREATE TABLE public.professionals (
    id character varying(255) NOT NULL,
    type character varying(50) NOT NULL,
    name character varying(255),
    title character varying(255),
    bio text,
    rate numeric,
    avatar text,
    socials jsonb,
    portfolio jsonb,
    hidden boolean DEFAULT false
);
 !   DROP TABLE public.professionals;
       public         heap r       rewardrush_user    false    5                       1259    18697    quest_questions    TABLE     �   CREATE TABLE public.quest_questions (
    id integer NOT NULL,
    quest_id integer NOT NULL,
    challenge_order integer NOT NULL,
    challenge_type character varying(50) NOT NULL,
    challenge_data jsonb NOT NULL
);
 #   DROP TABLE public.quest_questions;
       public         heap r       rewardrush_user    false    5            �            1259    17024    quest_questions_old    TABLE     �   CREATE TABLE public.quest_questions_old (
    id integer NOT NULL,
    quest_id integer,
    question_id character varying(255),
    question_type character varying(255),
    question_text text,
    options jsonb,
    correct_answer text
);
 '   DROP TABLE public.quest_questions_old;
       public         heap r       rewardrush_user    false    5            �            1259    17023    quest_questions_id_seq    SEQUENCE     �   CREATE SEQUENCE public.quest_questions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE public.quest_questions_id_seq;
       public               rewardrush_user    false    220    5            �           0    0    quest_questions_id_seq    SEQUENCE OWNED BY     U   ALTER SEQUENCE public.quest_questions_id_seq OWNED BY public.quest_questions_old.id;
          public               rewardrush_user    false    219                       1259    18696    quest_questions_id_seq1    SEQUENCE     �   CREATE SEQUENCE public.quest_questions_id_seq1
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.quest_questions_id_seq1;
       public               rewardrush_user    false    5    279            �           0    0    quest_questions_id_seq1    SEQUENCE OWNED BY     R   ALTER SEQUENCE public.quest_questions_id_seq1 OWNED BY public.quest_questions.id;
          public               rewardrush_user    false    278            �            1259    17174    quest_responses    TABLE     �   CREATE TABLE public.quest_responses (
    id integer NOT NULL,
    quest_id integer,
    username character varying(255),
    responses jsonb
);
 #   DROP TABLE public.quest_responses;
       public         heap r       rewardrush_user    false    5            �            1259    17173    quest_responses_id_seq    SEQUENCE     �   CREATE SEQUENCE public.quest_responses_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE public.quest_responses_id_seq;
       public               rewardrush_user    false    237    5            �           0    0    quest_responses_id_seq    SEQUENCE OWNED BY     Q   ALTER SEQUENCE public.quest_responses_id_seq OWNED BY public.quest_responses.id;
          public               rewardrush_user    false    236            �            1259    17013    quests    TABLE     �  CREATE TABLE public.quests (
    id integer NOT NULL,
    title text NOT NULL,
    description text,
    reward character varying(255),
    status character varying(50) DEFAULT 'Available'::character varying,
    start_time timestamp with time zone,
    end_time timestamp with time zone,
    participants integer DEFAULT 0,
    quiz_page text,
    quiz_background_url character varying(255),
    max_participants integer
);
    DROP TABLE public.quests;
       public         heap r       rewardrush_user    false    5            �            1259    17012    quests_id_seq    SEQUENCE     �   CREATE SEQUENCE public.quests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public.quests_id_seq;
       public               rewardrush_user    false    218    5            �           0    0    quests_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public.quests_id_seq OWNED BY public.quests.id;
          public               rewardrush_user    false    217                       1259    18567    referral_earnings    TABLE     �   CREATE TABLE public.referral_earnings (
    id integer NOT NULL,
    user_id integer NOT NULL,
    referral_id integer NOT NULL,
    amount numeric(10,2) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
 %   DROP TABLE public.referral_earnings;
       public         heap r       rewardrush_user    false    5                       1259    18566    referral_earnings_id_seq    SEQUENCE     �   CREATE SEQUENCE public.referral_earnings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 /   DROP SEQUENCE public.referral_earnings_id_seq;
       public               rewardrush_user    false    5    269            �           0    0    referral_earnings_id_seq    SEQUENCE OWNED BY     U   ALTER SEQUENCE public.referral_earnings_id_seq OWNED BY public.referral_earnings.id;
          public               rewardrush_user    false    268            �            1259    17183    referral_summary    TABLE     �   CREATE TABLE public.referral_summary (
    id integer NOT NULL,
    program_id integer,
    referrer_username character varying(255),
    referral_count integer
);
 $   DROP TABLE public.referral_summary;
       public         heap r       rewardrush_user    false    5            �            1259    17182    referral_summary_id_seq    SEQUENCE     �   CREATE SEQUENCE public.referral_summary_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.referral_summary_id_seq;
       public               rewardrush_user    false    239    5            �           0    0    referral_summary_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.referral_summary_id_seq OWNED BY public.referral_summary.id;
          public               rewardrush_user    false    238                       1259    18539 	   referrals    TABLE     v  CREATE TABLE public.referrals (
    id integer NOT NULL,
    referrer_id integer NOT NULL,
    referred_id integer NOT NULL,
    quest_id integer,
    type character varying(50) NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT referrals_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'completed'::character varying])::text[]))),
    CONSTRAINT referrals_type_check CHECK (((type)::text = ANY ((ARRAY['platform'::character varying, 'quest'::character varying])::text[])))
);
    DROP TABLE public.referrals;
       public         heap r       rewardrush_user    false    5            
           1259    18538    referrals_id_seq    SEQUENCE     �   CREATE SEQUENCE public.referrals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.referrals_id_seq;
       public               rewardrush_user    false    5    267            �           0    0    referrals_id_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.referrals_id_seq OWNED BY public.referrals.id;
          public               rewardrush_user    false    266            �            1259    18309    skill_expert_map    TABLE     v   CREATE TABLE public.skill_expert_map (
    skill_id character varying(50) NOT NULL,
    expert_id integer NOT NULL
);
 $   DROP TABLE public.skill_expert_map;
       public         heap r       rewardrush_user    false    5                       1259    18404    study_group_invitations    TABLE     .  CREATE TABLE public.study_group_invitations (
    id integer NOT NULL,
    study_group_id integer NOT NULL,
    inviter_id integer NOT NULL,
    invitee_id integer NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying,
    created_at timestamp with time zone DEFAULT now()
);
 +   DROP TABLE public.study_group_invitations;
       public         heap r       rewardrush_user    false    5                       1259    18403    study_group_invitations_id_seq    SEQUENCE     �   CREATE SEQUENCE public.study_group_invitations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 5   DROP SEQUENCE public.study_group_invitations_id_seq;
       public               rewardrush_user    false    263    5            �           0    0    study_group_invitations_id_seq    SEQUENCE OWNED BY     a   ALTER SEQUENCE public.study_group_invitations_id_seq OWNED BY public.study_group_invitations.id;
          public               rewardrush_user    false    262                       1259    18391    study_groups    TABLE     �   CREATE TABLE public.study_groups (
    id integer NOT NULL,
    skill_id character varying(255) NOT NULL,
    creator_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);
     DROP TABLE public.study_groups;
       public         heap r       rewardrush_user    false    5                       1259    18390    study_groups_id_seq    SEQUENCE     �   CREATE SEQUENCE public.study_groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE public.study_groups_id_seq;
       public               rewardrush_user    false    5    261            �           0    0    study_groups_id_seq    SEQUENCE OWNED BY     K   ALTER SEQUENCE public.study_groups_id_seq OWNED BY public.study_groups.id;
          public               rewardrush_user    false    260                        1259    18345    study_plan_days    TABLE     n   CREATE TABLE public.study_plan_days (
    study_plan_id integer NOT NULL,
    day_of_week integer NOT NULL
);
 #   DROP TABLE public.study_plan_days;
       public         heap r       rewardrush_user    false    5            �            1259    18325    study_plans    TABLE     %  CREATE TABLE public.study_plans (
    id integer NOT NULL,
    user_id integer NOT NULL,
    skill_id character varying(50) NOT NULL,
    goal text NOT NULL,
    reminder_time time without time zone,
    created_at timestamp with time zone DEFAULT now(),
    is_active boolean DEFAULT true
);
    DROP TABLE public.study_plans;
       public         heap r       rewardrush_user    false    5            �            1259    18324    study_plans_id_seq    SEQUENCE     �   CREATE SEQUENCE public.study_plans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.study_plans_id_seq;
       public               rewardrush_user    false    5    255            �           0    0    study_plans_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.study_plans_id_seq OWNED BY public.study_plans.id;
          public               rewardrush_user    false    254            �            1259    17487    tab_content    TABLE     �   CREATE TABLE public.tab_content (
    id integer NOT NULL,
    tab_id integer NOT NULL,
    title character varying(255),
    content text,
    link character varying(255)
);
    DROP TABLE public.tab_content;
       public         heap r       rewardrush_user    false    5            �            1259    17486    tab_content_id_seq    SEQUENCE     �   CREATE SEQUENCE public.tab_content_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.tab_content_id_seq;
       public               rewardrush_user    false    247    5            �           0    0    tab_content_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.tab_content_id_seq OWNED BY public.tab_content.id;
          public               rewardrush_user    false    246                       1259    18373    team_members    TABLE     3  CREATE TABLE public.team_members (
    team_id integer NOT NULL,
    user_id integer NOT NULL,
    invited_email character varying(255),
    status character varying(50) DEFAULT 'Pending'::character varying,
    invited_at timestamp with time zone DEFAULT now(),
    accepted_at timestamp with time zone
);
     DROP TABLE public.team_members;
       public         heap r       rewardrush_user    false    5                       1259    18356    teams    TABLE     �   CREATE TABLE public.teams (
    id integer NOT NULL,
    skill_id character varying(50) NOT NULL,
    creator_id integer NOT NULL,
    team_name character varying(255),
    created_at timestamp with time zone DEFAULT now()
);
    DROP TABLE public.teams;
       public         heap r       rewardrush_user    false    5                       1259    18355    teams_id_seq    SEQUENCE     �   CREATE SEQUENCE public.teams_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.teams_id_seq;
       public               rewardrush_user    false    258    5            �           0    0    teams_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.teams_id_seq OWNED BY public.teams.id;
          public               rewardrush_user    false    257            �            1259    17190    user_activity    TABLE     �   CREATE TABLE public.user_activity (
    id integer NOT NULL,
    user_id integer,
    activity_type character varying(255) NOT NULL,
    details text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
 !   DROP TABLE public.user_activity;
       public         heap r       rewardrush_user    false    5            �            1259    17189    user_activity_id_seq    SEQUENCE     �   CREATE SEQUENCE public.user_activity_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 +   DROP SEQUENCE public.user_activity_id_seq;
       public               rewardrush_user    false    241    5            �           0    0    user_activity_id_seq    SEQUENCE OWNED BY     M   ALTER SEQUENCE public.user_activity_id_seq OWNED BY public.user_activity.id;
          public               rewardrush_user    false    240                       1259    18588 	   user_jobs    TABLE     y  CREATE TABLE public.user_jobs (
    id integer NOT NULL,
    user_id integer NOT NULL,
    program_id integer NOT NULL,
    status character varying(50) DEFAULT 'pending_links'::character varying NOT NULL,
    onboarding_link text,
    tracking_link text,
    reward_amount numeric(10,2),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    submission_link text,
    rejection_reason text,
    cumulative_reward_paid numeric(10,2) DEFAULT 0.00 NOT NULL,
    current_claim_amount numeric(10,2),
    is_final_claim boolean DEFAULT false NOT NULL
);
    DROP TABLE public.user_jobs;
       public         heap r       rewardrush_user    false    5                       1259    18587    user_jobs_id_seq    SEQUENCE     �   CREATE SEQUENCE public.user_jobs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.user_jobs_id_seq;
       public               rewardrush_user    false    271    5            �           0    0    user_jobs_id_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.user_jobs_id_seq OWNED BY public.user_jobs.id;
          public               rewardrush_user    false    270            �            1259    18286    user_material_progress    TABLE     �   CREATE TABLE public.user_material_progress (
    user_id integer NOT NULL,
    material_id integer NOT NULL,
    completed_at timestamp with time zone DEFAULT now()
);
 *   DROP TABLE public.user_material_progress;
       public         heap r       rewardrush_user    false    5            �            1259    17038    user_quests    TABLE     �   CREATE TABLE public.user_quests (
    id integer NOT NULL,
    user_id integer,
    quest_id integer,
    completed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.user_quests;
       public         heap r       rewardrush_user    false    5            �            1259    17037    user_quests_id_seq    SEQUENCE     �   CREATE SEQUENCE public.user_quests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.user_quests_id_seq;
       public               rewardrush_user    false    222    5            �           0    0    user_quests_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.user_quests_id_seq OWNED BY public.user_quests.id;
          public               rewardrush_user    false    221            �            1259    16992    users    TABLE     �  CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    full_name character varying(255) NOT NULL,
    avatar text,
    points numeric(10,2) DEFAULT 0.00,
    blocked boolean DEFAULT false,
    twitter_handle character varying(255),
    wallet_address character varying(255),
    referral_code character varying(255),
    reset_password_token text,
    reset_password_expires timestamp with time zone,
    last_login timestamp with time zone,
    login_streak integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    bio text
);
    DROP TABLE public.users;
       public         heap r       rewardrush_user    false    5            �            1259    16991    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public               rewardrush_user    false    216    5            �           0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public               rewardrush_user    false    215            	           1259    18521    withdrawals    TABLE     �  CREATE TABLE public.withdrawals (
    id integer NOT NULL,
    user_id integer NOT NULL,
    amount numeric(10,2) NOT NULL,
    wallet_address character varying(255) NOT NULL,
    chain character varying(50) NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    transaction_hash character varying(255),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.withdrawals;
       public         heap r       rewardrush_user    false    5                       1259    18520    withdrawals_id_seq    SEQUENCE     �   CREATE SEQUENCE public.withdrawals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.withdrawals_id_seq;
       public               rewardrush_user    false    5    265            �           0    0    withdrawals_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.withdrawals_id_seq OWNED BY public.withdrawals.id;
          public               rewardrush_user    false    264            I           2604    17147    affiliate_clicks id    DEFAULT     z   ALTER TABLE ONLY public.affiliate_clicks ALTER COLUMN id SET DEFAULT nextval('public.affiliate_clicks_id_seq'::regclass);
 B   ALTER TABLE public.affiliate_clicks ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    233    232    233            A           2604    17061    affiliate_programs id    DEFAULT     ~   ALTER TABLE ONLY public.affiliate_programs ALTER COLUMN id SET DEFAULT nextval('public.affiliate_programs_id_seq'::regclass);
 D   ALTER TABLE public.affiliate_programs ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    224    223    224            F           2604    17126    bookings id    DEFAULT     j   ALTER TABLE ONLY public.bookings ALTER COLUMN id SET DEFAULT nextval('public.bookings_id_seq'::regclass);
 :   ALTER TABLE public.bookings ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    231    230    231            K           2604    17162    conversions id    DEFAULT     p   ALTER TABLE ONLY public.conversions ALTER COLUMN id SET DEFAULT nextval('public.conversions_id_seq'::regclass);
 =   ALTER TABLE public.conversions ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    234    235    235            D           2604    17103    education_categories id    DEFAULT     �   ALTER TABLE ONLY public.education_categories ALTER COLUMN id SET DEFAULT nextval('public.education_categories_id_seq'::regclass);
 F   ALTER TABLE public.education_categories ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    227    226    227            E           2604    17112    education_content id    DEFAULT     |   ALTER TABLE ONLY public.education_content ALTER COLUMN id SET DEFAULT nextval('public.education_content_id_seq'::regclass);
 C   ALTER TABLE public.education_content ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    229    228    229            n           2604    18617    job_completions id    DEFAULT     x   ALTER TABLE ONLY public.job_completions ALTER COLUMN id SET DEFAULT nextval('public.job_completions_id_seq'::regclass);
 A   ALTER TABLE public.job_completions ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    273    272    273            p           2604    18658    job_earnings id    DEFAULT     r   ALTER TABLE ONLY public.job_earnings ALTER COLUMN id SET DEFAULT nextval('public.job_earnings_id_seq'::regclass);
 >   ALTER TABLE public.job_earnings ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    275    274    275            s           2604    18682    notifications id    DEFAULT     t   ALTER TABLE ONLY public.notifications ALTER COLUMN id SET DEFAULT nextval('public.notifications_id_seq'::regclass);
 ?   ALTER TABLE public.notifications ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    277    276    277            Q           2604    17483    product_tabs id    DEFAULT     r   ALTER TABLE ONLY public.product_tabs ALTER COLUMN id SET DEFAULT nextval('public.product_tabs_id_seq'::regclass);
 >   ALTER TABLE public.product_tabs ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    244    245    245            v           2604    18700    quest_questions id    DEFAULT     y   ALTER TABLE ONLY public.quest_questions ALTER COLUMN id SET DEFAULT nextval('public.quest_questions_id_seq1'::regclass);
 A   ALTER TABLE public.quest_questions ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    278    279    279            >           2604    17027    quest_questions_old id    DEFAULT     |   ALTER TABLE ONLY public.quest_questions_old ALTER COLUMN id SET DEFAULT nextval('public.quest_questions_id_seq'::regclass);
 E   ALTER TABLE public.quest_questions_old ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    220    219    220            M           2604    17177    quest_responses id    DEFAULT     x   ALTER TABLE ONLY public.quest_responses ALTER COLUMN id SET DEFAULT nextval('public.quest_responses_id_seq'::regclass);
 A   ALTER TABLE public.quest_responses ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    236    237    237            ;           2604    17016 	   quests id    DEFAULT     f   ALTER TABLE ONLY public.quests ALTER COLUMN id SET DEFAULT nextval('public.quests_id_seq'::regclass);
 8   ALTER TABLE public.quests ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    218    217    218            f           2604    18570    referral_earnings id    DEFAULT     |   ALTER TABLE ONLY public.referral_earnings ALTER COLUMN id SET DEFAULT nextval('public.referral_earnings_id_seq'::regclass);
 C   ALTER TABLE public.referral_earnings ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    268    269    269            N           2604    17186    referral_summary id    DEFAULT     z   ALTER TABLE ONLY public.referral_summary ALTER COLUMN id SET DEFAULT nextval('public.referral_summary_id_seq'::regclass);
 B   ALTER TABLE public.referral_summary ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    238    239    239            c           2604    18542    referrals id    DEFAULT     l   ALTER TABLE ONLY public.referrals ALTER COLUMN id SET DEFAULT nextval('public.referrals_id_seq'::regclass);
 ;   ALTER TABLE public.referrals ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    266    267    267            ]           2604    18407    study_group_invitations id    DEFAULT     �   ALTER TABLE ONLY public.study_group_invitations ALTER COLUMN id SET DEFAULT nextval('public.study_group_invitations_id_seq'::regclass);
 I   ALTER TABLE public.study_group_invitations ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    262    263    263            [           2604    18394    study_groups id    DEFAULT     r   ALTER TABLE ONLY public.study_groups ALTER COLUMN id SET DEFAULT nextval('public.study_groups_id_seq'::regclass);
 >   ALTER TABLE public.study_groups ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    261    260    261            T           2604    18328    study_plans id    DEFAULT     p   ALTER TABLE ONLY public.study_plans ALTER COLUMN id SET DEFAULT nextval('public.study_plans_id_seq'::regclass);
 =   ALTER TABLE public.study_plans ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    254    255    255            R           2604    17490    tab_content id    DEFAULT     p   ALTER TABLE ONLY public.tab_content ALTER COLUMN id SET DEFAULT nextval('public.tab_content_id_seq'::regclass);
 =   ALTER TABLE public.tab_content ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    247    246    247            W           2604    18359    teams id    DEFAULT     d   ALTER TABLE ONLY public.teams ALTER COLUMN id SET DEFAULT nextval('public.teams_id_seq'::regclass);
 7   ALTER TABLE public.teams ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    258    257    258            O           2604    17193    user_activity id    DEFAULT     t   ALTER TABLE ONLY public.user_activity ALTER COLUMN id SET DEFAULT nextval('public.user_activity_id_seq'::regclass);
 ?   ALTER TABLE public.user_activity ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    240    241    241            h           2604    18591    user_jobs id    DEFAULT     l   ALTER TABLE ONLY public.user_jobs ALTER COLUMN id SET DEFAULT nextval('public.user_jobs_id_seq'::regclass);
 ;   ALTER TABLE public.user_jobs ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    271    270    271            ?           2604    17041    user_quests id    DEFAULT     p   ALTER TABLE ONLY public.user_quests ALTER COLUMN id SET DEFAULT nextval('public.user_quests_id_seq'::regclass);
 =   ALTER TABLE public.user_quests ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    222    221    222            6           2604    16995    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    216    215    216            `           2604    18524    withdrawals id    DEFAULT     p   ALTER TABLE ONLY public.withdrawals ALTER COLUMN id SET DEFAULT nextval('public.withdrawals_id_seq'::regclass);
 =   ALTER TABLE public.withdrawals ALTER COLUMN id DROP DEFAULT;
       public               rewardrush_user    false    264    265    265            �          0    17144    affiliate_clicks 
   TABLE DATA           g   COPY public.affiliate_clicks (id, program_id, affiliate_username, ip_address, "timestamp") FROM stdin;
    public               rewardrush_user    false    233   ؍      �          0    17058    affiliate_programs 
   TABLE DATA           �   COPY public.affiliate_programs (id, category, title, guidelines, details, pros, cons, payout, destination_url, brand_website, social_links, brand_dashboard_url, max_participants, status) FROM stdin;
    public               rewardrush_user    false    224   ��      �          0    17123    bookings 
   TABLE DATA           l   COPY public.bookings (id, user_id, professional_id, reason, preferred_date, status, created_at) FROM stdin;
    public               rewardrush_user    false    231   I�      �          0    17159    conversions 
   TABLE DATA           w   COPY public.conversions (id, program_id, affiliate_username, conversion_value, payout_amount, "timestamp") FROM stdin;
    public               rewardrush_user    false    235   f�      �          0    17100    education_categories 
   TABLE DATA           8   COPY public.education_categories (id, name) FROM stdin;
    public               rewardrush_user    false    227   ��      �          0    17109    education_content 
   TABLE DATA           n   COPY public.education_content (id, category_id, content_id, title, type, source, author, summary) FROM stdin;
    public               rewardrush_user    false    229   �      �          0    18302    education_experts 
   TABLE DATA           ]   COPY public.education_experts (id, name, title, avatar, bio, socials, portfolio) FROM stdin;
    public               rewardrush_user    false    252    �      �          0    18274    education_materials 
   TABLE DATA           X   COPY public.education_materials (id, skill_id, title, type, duration, link) FROM stdin;
    public               rewardrush_user    false    250   a�      �          0    18267    education_skills 
   TABLE DATA           _   COPY public.education_skills (id, title, icon, color, courses, hours, description) FROM stdin;
    public               rewardrush_user    false    249   ׸      �          0    17465    experts 
   TABLE DATA           A   COPY public.experts (id, name, title, avatar, color) FROM stdin;
    public               rewardrush_user    false    242   Y�      �          0    18614    job_completions 
   TABLE DATA           _   COPY public.job_completions (id, user_id, program_id, reward_amount, completed_at) FROM stdin;
    public               rewardrush_user    false    273   ]�      �          0    18655    job_earnings 
   TABLE DATA           r   COPY public.job_earnings (id, user_id, program_id, user_job_id, amount, is_final_payment, created_at) FROM stdin;
    public               rewardrush_user    false    275   ��      �          0    18679    notifications 
   TABLE DATA           R   COPY public.notifications (id, user_id, message, is_read, created_at) FROM stdin;
    public               rewardrush_user    false    277   8�      �          0    17495    product_expert_map 
   TABLE DATA           C   COPY public.product_expert_map (product_id, expert_id) FROM stdin;
    public               rewardrush_user    false    248   U�      �          0    17480    product_tabs 
   TABLE DATA           L   COPY public.product_tabs (id, product_id, tab_key, title, icon) FROM stdin;
    public               rewardrush_user    false    245   ��      �          0    17472    products 
   TABLE DATA           g   COPY public.products (id, title, icon, color, description, guide_title, guide_description) FROM stdin;
    public               rewardrush_user    false    243   N�      �          0    17091    professionals 
   TABLE DATA           m   COPY public.professionals (id, type, name, title, bio, rate, avatar, socials, portfolio, hidden) FROM stdin;
    public               rewardrush_user    false    225   1�      �          0    18697    quest_questions 
   TABLE DATA           h   COPY public.quest_questions (id, quest_id, challenge_order, challenge_type, challenge_data) FROM stdin;
    public               rewardrush_user    false    279   N�      �          0    17024    quest_questions_old 
   TABLE DATA              COPY public.quest_questions_old (id, quest_id, question_id, question_type, question_text, options, correct_answer) FROM stdin;
    public               rewardrush_user    false    220   ��      �          0    17174    quest_responses 
   TABLE DATA           L   COPY public.quest_responses (id, quest_id, username, responses) FROM stdin;
    public               rewardrush_user    false    237   E�      �          0    17013    quests 
   TABLE DATA           �   COPY public.quests (id, title, description, reward, status, start_time, end_time, participants, quiz_page, quiz_background_url, max_participants) FROM stdin;
    public               rewardrush_user    false    218   b�      �          0    18567    referral_earnings 
   TABLE DATA           Y   COPY public.referral_earnings (id, user_id, referral_id, amount, created_at) FROM stdin;
    public               rewardrush_user    false    269   ��      �          0    17183    referral_summary 
   TABLE DATA           ]   COPY public.referral_summary (id, program_id, referrer_username, referral_count) FROM stdin;
    public               rewardrush_user    false    239   V�      �          0    18539 	   referrals 
   TABLE DATA           e   COPY public.referrals (id, referrer_id, referred_id, quest_id, type, status, created_at) FROM stdin;
    public               rewardrush_user    false    267   s�      �          0    18309    skill_expert_map 
   TABLE DATA           ?   COPY public.skill_expert_map (skill_id, expert_id) FROM stdin;
    public               rewardrush_user    false    253    �      �          0    18404    study_group_invitations 
   TABLE DATA           q   COPY public.study_group_invitations (id, study_group_id, inviter_id, invitee_id, status, created_at) FROM stdin;
    public               rewardrush_user    false    263   ��      �          0    18391    study_groups 
   TABLE DATA           L   COPY public.study_groups (id, skill_id, creator_id, created_at) FROM stdin;
    public               rewardrush_user    false    261   ��      �          0    18345    study_plan_days 
   TABLE DATA           E   COPY public.study_plan_days (study_plan_id, day_of_week) FROM stdin;
    public               rewardrush_user    false    256   ��      �          0    18325    study_plans 
   TABLE DATA           h   COPY public.study_plans (id, user_id, skill_id, goal, reminder_time, created_at, is_active) FROM stdin;
    public               rewardrush_user    false    255   ��      �          0    17487    tab_content 
   TABLE DATA           G   COPY public.tab_content (id, tab_id, title, content, link) FROM stdin;
    public               rewardrush_user    false    247   ��      �          0    18373    team_members 
   TABLE DATA           h   COPY public.team_members (team_id, user_id, invited_email, status, invited_at, accepted_at) FROM stdin;
    public               rewardrush_user    false    259   ��      �          0    18356    teams 
   TABLE DATA           P   COPY public.teams (id, skill_id, creator_id, team_name, created_at) FROM stdin;
    public               rewardrush_user    false    258   ��      �          0    17190    user_activity 
   TABLE DATA           X   COPY public.user_activity (id, user_id, activity_type, details, created_at) FROM stdin;
    public               rewardrush_user    false    241   ��      �          0    18588 	   user_jobs 
   TABLE DATA           �   COPY public.user_jobs (id, user_id, program_id, status, onboarding_link, tracking_link, reward_amount, created_at, updated_at, submission_link, rejection_reason, cumulative_reward_paid, current_claim_amount, is_final_claim) FROM stdin;
    public               rewardrush_user    false    271   �      �          0    18286    user_material_progress 
   TABLE DATA           T   COPY public.user_material_progress (user_id, material_id, completed_at) FROM stdin;
    public               rewardrush_user    false    251   ��      �          0    17038    user_quests 
   TABLE DATA           J   COPY public.user_quests (id, user_id, quest_id, completed_at) FROM stdin;
    public               rewardrush_user    false    222   F�      �          0    16992    users 
   TABLE DATA           �   COPY public.users (id, username, email, password_hash, full_name, avatar, points, blocked, twitter_handle, wallet_address, referral_code, reset_password_token, reset_password_expires, last_login, login_streak, created_at, bio) FROM stdin;
    public               rewardrush_user    false    216   d�      �          0    18521    withdrawals 
   TABLE DATA           w   COPY public.withdrawals (id, user_id, amount, wallet_address, chain, status, transaction_hash, created_at) FROM stdin;
    public               rewardrush_user    false    265   ��                  0    0    affiliate_clicks_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.affiliate_clicks_id_seq', 1, false);
          public               rewardrush_user    false    232                       0    0    affiliate_programs_id_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.affiliate_programs_id_seq', 1, false);
          public               rewardrush_user    false    223                       0    0    bookings_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.bookings_id_seq', 1, false);
          public               rewardrush_user    false    230                       0    0    conversions_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.conversions_id_seq', 1, false);
          public               rewardrush_user    false    234                       0    0    education_categories_id_seq    SEQUENCE SET     I   SELECT pg_catalog.setval('public.education_categories_id_seq', 8, true);
          public               rewardrush_user    false    226                       0    0    education_content_id_seq    SEQUENCE SET     G   SELECT pg_catalog.setval('public.education_content_id_seq', 32, true);
          public               rewardrush_user    false    228                       0    0    job_completions_id_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('public.job_completions_id_seq', 1, true);
          public               rewardrush_user    false    272                       0    0    job_earnings_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.job_earnings_id_seq', 6, true);
          public               rewardrush_user    false    274                       0    0    notifications_id_seq    SEQUENCE SET     C   SELECT pg_catalog.setval('public.notifications_id_seq', 1, false);
          public               rewardrush_user    false    276            	           0    0    product_tabs_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('public.product_tabs_id_seq', 12, true);
          public               rewardrush_user    false    244            
           0    0    quest_questions_id_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('public.quest_questions_id_seq', 20, true);
          public               rewardrush_user    false    219                       0    0    quest_questions_id_seq1    SEQUENCE SET     F   SELECT pg_catalog.setval('public.quest_questions_id_seq1', 59, true);
          public               rewardrush_user    false    278                       0    0    quest_responses_id_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('public.quest_responses_id_seq', 1, false);
          public               rewardrush_user    false    236                       0    0    quests_id_seq    SEQUENCE SET     <   SELECT pg_catalog.setval('public.quests_id_seq', 10, true);
          public               rewardrush_user    false    217                       0    0    referral_earnings_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.referral_earnings_id_seq', 4, true);
          public               rewardrush_user    false    268                       0    0    referral_summary_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.referral_summary_id_seq', 1, false);
          public               rewardrush_user    false    238                       0    0    referrals_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.referrals_id_seq', 4, true);
          public               rewardrush_user    false    266                       0    0    study_group_invitations_id_seq    SEQUENCE SET     M   SELECT pg_catalog.setval('public.study_group_invitations_id_seq', 18, true);
          public               rewardrush_user    false    262                       0    0    study_groups_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.study_groups_id_seq', 7, true);
          public               rewardrush_user    false    260                       0    0    study_plans_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.study_plans_id_seq', 1, false);
          public               rewardrush_user    false    254                       0    0    tab_content_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.tab_content_id_seq', 30, true);
          public               rewardrush_user    false    246                       0    0    teams_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.teams_id_seq', 1, false);
          public               rewardrush_user    false    257                       0    0    user_activity_id_seq    SEQUENCE SET     C   SELECT pg_catalog.setval('public.user_activity_id_seq', 20, true);
          public               rewardrush_user    false    240                       0    0    user_jobs_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.user_jobs_id_seq', 4, true);
          public               rewardrush_user    false    270                       0    0    user_quests_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.user_quests_id_seq', 17, true);
          public               rewardrush_user    false    221                       0    0    users_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.users_id_seq', 19, true);
          public               rewardrush_user    false    215                       0    0    withdrawals_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.withdrawals_id_seq', 5, true);
          public               rewardrush_user    false    264            �           2606    17152 &   affiliate_clicks affiliate_clicks_pkey 
   CONSTRAINT     d   ALTER TABLE ONLY public.affiliate_clicks
    ADD CONSTRAINT affiliate_clicks_pkey PRIMARY KEY (id);
 P   ALTER TABLE ONLY public.affiliate_clicks DROP CONSTRAINT affiliate_clicks_pkey;
       public                 rewardrush_user    false    233            �           2606    17065 *   affiliate_programs affiliate_programs_pkey 
   CONSTRAINT     h   ALTER TABLE ONLY public.affiliate_programs
    ADD CONSTRAINT affiliate_programs_pkey PRIMARY KEY (id);
 T   ALTER TABLE ONLY public.affiliate_programs DROP CONSTRAINT affiliate_programs_pkey;
       public                 rewardrush_user    false    224            �           2606    17132    bookings bookings_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.bookings
    ADD CONSTRAINT bookings_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.bookings DROP CONSTRAINT bookings_pkey;
       public                 rewardrush_user    false    231            �           2606    17167    conversions conversions_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.conversions
    ADD CONSTRAINT conversions_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.conversions DROP CONSTRAINT conversions_pkey;
       public                 rewardrush_user    false    235            �           2606    17107 2   education_categories education_categories_name_key 
   CONSTRAINT     m   ALTER TABLE ONLY public.education_categories
    ADD CONSTRAINT education_categories_name_key UNIQUE (name);
 \   ALTER TABLE ONLY public.education_categories DROP CONSTRAINT education_categories_name_key;
       public                 rewardrush_user    false    227            �           2606    17105 .   education_categories education_categories_pkey 
   CONSTRAINT     l   ALTER TABLE ONLY public.education_categories
    ADD CONSTRAINT education_categories_pkey PRIMARY KEY (id);
 X   ALTER TABLE ONLY public.education_categories DROP CONSTRAINT education_categories_pkey;
       public                 rewardrush_user    false    227            �           2606    17116 (   education_content education_content_pkey 
   CONSTRAINT     f   ALTER TABLE ONLY public.education_content
    ADD CONSTRAINT education_content_pkey PRIMARY KEY (id);
 R   ALTER TABLE ONLY public.education_content DROP CONSTRAINT education_content_pkey;
       public                 rewardrush_user    false    229            �           2606    18308 (   education_experts education_experts_pkey 
   CONSTRAINT     f   ALTER TABLE ONLY public.education_experts
    ADD CONSTRAINT education_experts_pkey PRIMARY KEY (id);
 R   ALTER TABLE ONLY public.education_experts DROP CONSTRAINT education_experts_pkey;
       public                 rewardrush_user    false    252            �           2606    18280 ,   education_materials education_materials_pkey 
   CONSTRAINT     j   ALTER TABLE ONLY public.education_materials
    ADD CONSTRAINT education_materials_pkey PRIMARY KEY (id);
 V   ALTER TABLE ONLY public.education_materials DROP CONSTRAINT education_materials_pkey;
       public                 rewardrush_user    false    250            �           2606    18273 &   education_skills education_skills_pkey 
   CONSTRAINT     d   ALTER TABLE ONLY public.education_skills
    ADD CONSTRAINT education_skills_pkey PRIMARY KEY (id);
 P   ALTER TABLE ONLY public.education_skills DROP CONSTRAINT education_skills_pkey;
       public                 rewardrush_user    false    249            �           2606    17471    experts experts_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.experts
    ADD CONSTRAINT experts_pkey PRIMARY KEY (id);
 >   ALTER TABLE ONLY public.experts DROP CONSTRAINT experts_pkey;
       public                 rewardrush_user    false    242            �           2606    18620 $   job_completions job_completions_pkey 
   CONSTRAINT     b   ALTER TABLE ONLY public.job_completions
    ADD CONSTRAINT job_completions_pkey PRIMARY KEY (id);
 N   ALTER TABLE ONLY public.job_completions DROP CONSTRAINT job_completions_pkey;
       public                 rewardrush_user    false    273            �           2606    18662    job_earnings job_earnings_pkey 
   CONSTRAINT     \   ALTER TABLE ONLY public.job_earnings
    ADD CONSTRAINT job_earnings_pkey PRIMARY KEY (id);
 H   ALTER TABLE ONLY public.job_earnings DROP CONSTRAINT job_earnings_pkey;
       public                 rewardrush_user    false    275            �           2606    18688     notifications notifications_pkey 
   CONSTRAINT     ^   ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);
 J   ALTER TABLE ONLY public.notifications DROP CONSTRAINT notifications_pkey;
       public                 rewardrush_user    false    277            �           2606    17499 *   product_expert_map product_expert_map_pkey 
   CONSTRAINT     {   ALTER TABLE ONLY public.product_expert_map
    ADD CONSTRAINT product_expert_map_pkey PRIMARY KEY (product_id, expert_id);
 T   ALTER TABLE ONLY public.product_expert_map DROP CONSTRAINT product_expert_map_pkey;
       public                 rewardrush_user    false    248    248            �           2606    17485    product_tabs product_tabs_pkey 
   CONSTRAINT     \   ALTER TABLE ONLY public.product_tabs
    ADD CONSTRAINT product_tabs_pkey PRIMARY KEY (id);
 H   ALTER TABLE ONLY public.product_tabs DROP CONSTRAINT product_tabs_pkey;
       public                 rewardrush_user    false    245            �           2606    17478    products products_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.products DROP CONSTRAINT products_pkey;
       public                 rewardrush_user    false    243            �           2606    17098     professionals professionals_pkey 
   CONSTRAINT     ^   ALTER TABLE ONLY public.professionals
    ADD CONSTRAINT professionals_pkey PRIMARY KEY (id);
 J   ALTER TABLE ONLY public.professionals DROP CONSTRAINT professionals_pkey;
       public                 rewardrush_user    false    225            �           2606    18706 ,   quest_questions quest_challenge_order_unique 
   CONSTRAINT     |   ALTER TABLE ONLY public.quest_questions
    ADD CONSTRAINT quest_challenge_order_unique UNIQUE (quest_id, challenge_order);
 V   ALTER TABLE ONLY public.quest_questions DROP CONSTRAINT quest_challenge_order_unique;
       public                 rewardrush_user    false    279    279            �           2606    17031 (   quest_questions_old quest_questions_pkey 
   CONSTRAINT     f   ALTER TABLE ONLY public.quest_questions_old
    ADD CONSTRAINT quest_questions_pkey PRIMARY KEY (id);
 R   ALTER TABLE ONLY public.quest_questions_old DROP CONSTRAINT quest_questions_pkey;
       public                 rewardrush_user    false    220            �           2606    18704 %   quest_questions quest_questions_pkey1 
   CONSTRAINT     c   ALTER TABLE ONLY public.quest_questions
    ADD CONSTRAINT quest_questions_pkey1 PRIMARY KEY (id);
 O   ALTER TABLE ONLY public.quest_questions DROP CONSTRAINT quest_questions_pkey1;
       public                 rewardrush_user    false    279            �           2606    17181 $   quest_responses quest_responses_pkey 
   CONSTRAINT     b   ALTER TABLE ONLY public.quest_responses
    ADD CONSTRAINT quest_responses_pkey PRIMARY KEY (id);
 N   ALTER TABLE ONLY public.quest_responses DROP CONSTRAINT quest_responses_pkey;
       public                 rewardrush_user    false    237            �           2606    17022    quests quests_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public.quests
    ADD CONSTRAINT quests_pkey PRIMARY KEY (id);
 <   ALTER TABLE ONLY public.quests DROP CONSTRAINT quests_pkey;
       public                 rewardrush_user    false    218            �           2606    18573 (   referral_earnings referral_earnings_pkey 
   CONSTRAINT     f   ALTER TABLE ONLY public.referral_earnings
    ADD CONSTRAINT referral_earnings_pkey PRIMARY KEY (id);
 R   ALTER TABLE ONLY public.referral_earnings DROP CONSTRAINT referral_earnings_pkey;
       public                 rewardrush_user    false    269            �           2606    17188 &   referral_summary referral_summary_pkey 
   CONSTRAINT     d   ALTER TABLE ONLY public.referral_summary
    ADD CONSTRAINT referral_summary_pkey PRIMARY KEY (id);
 P   ALTER TABLE ONLY public.referral_summary DROP CONSTRAINT referral_summary_pkey;
       public                 rewardrush_user    false    239            �           2606    18548    referrals referrals_pkey 
   CONSTRAINT     V   ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT referrals_pkey PRIMARY KEY (id);
 B   ALTER TABLE ONLY public.referrals DROP CONSTRAINT referrals_pkey;
       public                 rewardrush_user    false    267            �           2606    18550 8   referrals referrals_referrer_id_referred_id_quest_id_key 
   CONSTRAINT     �   ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT referrals_referrer_id_referred_id_quest_id_key UNIQUE (referrer_id, referred_id, quest_id);
 b   ALTER TABLE ONLY public.referrals DROP CONSTRAINT referrals_referrer_id_referred_id_quest_id_key;
       public                 rewardrush_user    false    267    267    267            �           2606    18313 &   skill_expert_map skill_expert_map_pkey 
   CONSTRAINT     u   ALTER TABLE ONLY public.skill_expert_map
    ADD CONSTRAINT skill_expert_map_pkey PRIMARY KEY (skill_id, expert_id);
 P   ALTER TABLE ONLY public.skill_expert_map DROP CONSTRAINT skill_expert_map_pkey;
       public                 rewardrush_user    false    253    253            �           2606    18411 4   study_group_invitations study_group_invitations_pkey 
   CONSTRAINT     r   ALTER TABLE ONLY public.study_group_invitations
    ADD CONSTRAINT study_group_invitations_pkey PRIMARY KEY (id);
 ^   ALTER TABLE ONLY public.study_group_invitations DROP CONSTRAINT study_group_invitations_pkey;
       public                 rewardrush_user    false    263            �           2606    18413 M   study_group_invitations study_group_invitations_study_group_id_invitee_id_key 
   CONSTRAINT     �   ALTER TABLE ONLY public.study_group_invitations
    ADD CONSTRAINT study_group_invitations_study_group_id_invitee_id_key UNIQUE (study_group_id, invitee_id);
 w   ALTER TABLE ONLY public.study_group_invitations DROP CONSTRAINT study_group_invitations_study_group_id_invitee_id_key;
       public                 rewardrush_user    false    263    263            �           2606    18397    study_groups study_groups_pkey 
   CONSTRAINT     \   ALTER TABLE ONLY public.study_groups
    ADD CONSTRAINT study_groups_pkey PRIMARY KEY (id);
 H   ALTER TABLE ONLY public.study_groups DROP CONSTRAINT study_groups_pkey;
       public                 rewardrush_user    false    261            �           2606    18349 $   study_plan_days study_plan_days_pkey 
   CONSTRAINT     z   ALTER TABLE ONLY public.study_plan_days
    ADD CONSTRAINT study_plan_days_pkey PRIMARY KEY (study_plan_id, day_of_week);
 N   ALTER TABLE ONLY public.study_plan_days DROP CONSTRAINT study_plan_days_pkey;
       public                 rewardrush_user    false    256    256            �           2606    18334    study_plans study_plans_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.study_plans
    ADD CONSTRAINT study_plans_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.study_plans DROP CONSTRAINT study_plans_pkey;
       public                 rewardrush_user    false    255            �           2606    17494    tab_content tab_content_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.tab_content
    ADD CONSTRAINT tab_content_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.tab_content DROP CONSTRAINT tab_content_pkey;
       public                 rewardrush_user    false    247            �           2606    18379    team_members team_members_pkey 
   CONSTRAINT     j   ALTER TABLE ONLY public.team_members
    ADD CONSTRAINT team_members_pkey PRIMARY KEY (team_id, user_id);
 H   ALTER TABLE ONLY public.team_members DROP CONSTRAINT team_members_pkey;
       public                 rewardrush_user    false    259    259            �           2606    18362    teams teams_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.teams
    ADD CONSTRAINT teams_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.teams DROP CONSTRAINT teams_pkey;
       public                 rewardrush_user    false    258            �           2606    17198     user_activity user_activity_pkey 
   CONSTRAINT     ^   ALTER TABLE ONLY public.user_activity
    ADD CONSTRAINT user_activity_pkey PRIMARY KEY (id);
 J   ALTER TABLE ONLY public.user_activity DROP CONSTRAINT user_activity_pkey;
       public                 rewardrush_user    false    241            �           2606    18598    user_jobs user_jobs_pkey 
   CONSTRAINT     V   ALTER TABLE ONLY public.user_jobs
    ADD CONSTRAINT user_jobs_pkey PRIMARY KEY (id);
 B   ALTER TABLE ONLY public.user_jobs DROP CONSTRAINT user_jobs_pkey;
       public                 rewardrush_user    false    271            �           2606    18600 *   user_jobs user_jobs_user_id_program_id_key 
   CONSTRAINT     t   ALTER TABLE ONLY public.user_jobs
    ADD CONSTRAINT user_jobs_user_id_program_id_key UNIQUE (user_id, program_id);
 T   ALTER TABLE ONLY public.user_jobs DROP CONSTRAINT user_jobs_user_id_program_id_key;
       public                 rewardrush_user    false    271    271            �           2606    18291 2   user_material_progress user_material_progress_pkey 
   CONSTRAINT     �   ALTER TABLE ONLY public.user_material_progress
    ADD CONSTRAINT user_material_progress_pkey PRIMARY KEY (user_id, material_id);
 \   ALTER TABLE ONLY public.user_material_progress DROP CONSTRAINT user_material_progress_pkey;
       public                 rewardrush_user    false    251    251            �           2606    17044    user_quests user_quests_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.user_quests
    ADD CONSTRAINT user_quests_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.user_quests DROP CONSTRAINT user_quests_pkey;
       public                 rewardrush_user    false    222            �           2606    17046 ,   user_quests user_quests_user_id_quest_id_key 
   CONSTRAINT     t   ALTER TABLE ONLY public.user_quests
    ADD CONSTRAINT user_quests_user_id_quest_id_key UNIQUE (user_id, quest_id);
 V   ALTER TABLE ONLY public.user_quests DROP CONSTRAINT user_quests_user_id_quest_id_key;
       public                 rewardrush_user    false    222    222            {           2606    17007    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public                 rewardrush_user    false    216            }           2606    17003    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public                 rewardrush_user    false    216                       2606    17011    users users_referral_code_key 
   CONSTRAINT     a   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_referral_code_key UNIQUE (referral_code);
 G   ALTER TABLE ONLY public.users DROP CONSTRAINT users_referral_code_key;
       public                 rewardrush_user    false    216            �           2606    17005    users users_username_key 
   CONSTRAINT     W   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);
 B   ALTER TABLE ONLY public.users DROP CONSTRAINT users_username_key;
       public                 rewardrush_user    false    216            �           2606    17009    users users_wallet_address_key 
   CONSTRAINT     c   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_wallet_address_key UNIQUE (wallet_address);
 H   ALTER TABLE ONLY public.users DROP CONSTRAINT users_wallet_address_key;
       public                 rewardrush_user    false    216            �           2606    18530    withdrawals withdrawals_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.withdrawals
    ADD CONSTRAINT withdrawals_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.withdrawals DROP CONSTRAINT withdrawals_pkey;
       public                 rewardrush_user    false    265            �           1259    17208 '   idx_affiliate_clicks_affiliate_username    INDEX     r   CREATE INDEX idx_affiliate_clicks_affiliate_username ON public.affiliate_clicks USING btree (affiliate_username);
 ;   DROP INDEX public.idx_affiliate_clicks_affiliate_username;
       public                 rewardrush_user    false    233            �           1259    17209    idx_bookings_user_id    INDEX     L   CREATE INDEX idx_bookings_user_id ON public.bookings USING btree (user_id);
 (   DROP INDEX public.idx_bookings_user_id;
       public                 rewardrush_user    false    231            �           1259    17207 "   idx_conversions_affiliate_username    INDEX     h   CREATE INDEX idx_conversions_affiliate_username ON public.conversions USING btree (affiliate_username);
 6   DROP INDEX public.idx_conversions_affiliate_username;
       public                 rewardrush_user    false    235            �           1259    18631    idx_job_completions_user_id    INDEX     Z   CREATE INDEX idx_job_completions_user_id ON public.job_completions USING btree (user_id);
 /   DROP INDEX public.idx_job_completions_user_id;
       public                 rewardrush_user    false    273            �           1259    18694    idx_notifications_user_id    INDEX     V   CREATE INDEX idx_notifications_user_id ON public.notifications USING btree (user_id);
 -   DROP INDEX public.idx_notifications_user_id;
       public                 rewardrush_user    false    277            �           1259    18586    idx_referral_earnings_user_id    INDEX     ^   CREATE INDEX idx_referral_earnings_user_id ON public.referral_earnings USING btree (user_id);
 1   DROP INDEX public.idx_referral_earnings_user_id;
       public                 rewardrush_user    false    269            �           1259    18585    idx_referrals_referred_id    INDEX     V   CREATE INDEX idx_referrals_referred_id ON public.referrals USING btree (referred_id);
 -   DROP INDEX public.idx_referrals_referred_id;
       public                 rewardrush_user    false    267            �           1259    18584    idx_referrals_referrer_id    INDEX     V   CREATE INDEX idx_referrals_referrer_id ON public.referrals USING btree (referrer_id);
 -   DROP INDEX public.idx_referrals_referrer_id;
       public                 rewardrush_user    false    267            �           1259    17210    idx_user_activity_user_id    INDEX     V   CREATE INDEX idx_user_activity_user_id ON public.user_activity USING btree (user_id);
 -   DROP INDEX public.idx_user_activity_user_id;
       public                 rewardrush_user    false    241            �           1259    17206    idx_user_quests_user_id    INDEX     R   CREATE INDEX idx_user_quests_user_id ON public.user_quests USING btree (user_id);
 +   DROP INDEX public.idx_user_quests_user_id;
       public                 rewardrush_user    false    222            y           1259    17205    idx_users_username    INDEX     H   CREATE INDEX idx_users_username ON public.users USING btree (username);
 &   DROP INDEX public.idx_users_username;
       public                 rewardrush_user    false    216            �           1259    18537    idx_withdrawals_status    INDEX     P   CREATE INDEX idx_withdrawals_status ON public.withdrawals USING btree (status);
 *   DROP INDEX public.idx_withdrawals_status;
       public                 rewardrush_user    false    265            �           1259    18536    idx_withdrawals_user_id    INDEX     R   CREATE INDEX idx_withdrawals_user_id ON public.withdrawals USING btree (user_id);
 +   DROP INDEX public.idx_withdrawals_user_id;
       public                 rewardrush_user    false    265            �           2606    17153 1   affiliate_clicks affiliate_clicks_program_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.affiliate_clicks
    ADD CONSTRAINT affiliate_clicks_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.affiliate_programs(id);
 [   ALTER TABLE ONLY public.affiliate_clicks DROP CONSTRAINT affiliate_clicks_program_id_fkey;
       public               rewardrush_user    false    233    224    3470            �           2606    17138 &   bookings bookings_professional_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.bookings
    ADD CONSTRAINT bookings_professional_id_fkey FOREIGN KEY (professional_id) REFERENCES public.professionals(id) ON DELETE CASCADE;
 P   ALTER TABLE ONLY public.bookings DROP CONSTRAINT bookings_professional_id_fkey;
       public               rewardrush_user    false    231    225    3472            �           2606    17133    bookings bookings_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.bookings
    ADD CONSTRAINT bookings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 H   ALTER TABLE ONLY public.bookings DROP CONSTRAINT bookings_user_id_fkey;
       public               rewardrush_user    false    231    216    3453            �           2606    17168 '   conversions conversions_program_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.conversions
    ADD CONSTRAINT conversions_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.affiliate_programs(id);
 Q   ALTER TABLE ONLY public.conversions DROP CONSTRAINT conversions_program_id_fkey;
       public               rewardrush_user    false    235    3470    224            �           2606    17117 4   education_content education_content_category_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.education_content
    ADD CONSTRAINT education_content_category_id_fkey FOREIGN KEY (category_id) REFERENCES public.education_categories(id) ON DELETE CASCADE;
 ^   ALTER TABLE ONLY public.education_content DROP CONSTRAINT education_content_category_id_fkey;
       public               rewardrush_user    false    3476    227    229            �           2606    18281 5   education_materials education_materials_skill_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.education_materials
    ADD CONSTRAINT education_materials_skill_id_fkey FOREIGN KEY (skill_id) REFERENCES public.education_skills(id) ON DELETE CASCADE;
 _   ALTER TABLE ONLY public.education_materials DROP CONSTRAINT education_materials_skill_id_fkey;
       public               rewardrush_user    false    249    250    3506            �           2606    18531    withdrawals fk_user    FK CONSTRAINT     �   ALTER TABLE ONLY public.withdrawals
    ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 =   ALTER TABLE ONLY public.withdrawals DROP CONSTRAINT fk_user;
       public               rewardrush_user    false    265    3453    216                       2606    18626 /   job_completions job_completions_program_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.job_completions
    ADD CONSTRAINT job_completions_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.affiliate_programs(id) ON DELETE CASCADE;
 Y   ALTER TABLE ONLY public.job_completions DROP CONSTRAINT job_completions_program_id_fkey;
       public               rewardrush_user    false    3470    224    273                       2606    18621 ,   job_completions job_completions_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.job_completions
    ADD CONSTRAINT job_completions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 V   ALTER TABLE ONLY public.job_completions DROP CONSTRAINT job_completions_user_id_fkey;
       public               rewardrush_user    false    3453    216    273            	           2606    18668 )   job_earnings job_earnings_program_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.job_earnings
    ADD CONSTRAINT job_earnings_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.affiliate_programs(id) ON DELETE CASCADE;
 S   ALTER TABLE ONLY public.job_earnings DROP CONSTRAINT job_earnings_program_id_fkey;
       public               rewardrush_user    false    224    275    3470            
           2606    18663 &   job_earnings job_earnings_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.job_earnings
    ADD CONSTRAINT job_earnings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 P   ALTER TABLE ONLY public.job_earnings DROP CONSTRAINT job_earnings_user_id_fkey;
       public               rewardrush_user    false    275    3453    216                       2606    18673 *   job_earnings job_earnings_user_job_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.job_earnings
    ADD CONSTRAINT job_earnings_user_job_id_fkey FOREIGN KEY (user_job_id) REFERENCES public.user_jobs(id) ON DELETE SET NULL;
 T   ALTER TABLE ONLY public.job_earnings DROP CONSTRAINT job_earnings_user_job_id_fkey;
       public               rewardrush_user    false    271    3543    275                       2606    18689 (   notifications notifications_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 R   ALTER TABLE ONLY public.notifications DROP CONSTRAINT notifications_user_id_fkey;
       public               rewardrush_user    false    3453    216    277            �           2606    17032 1   quest_questions_old quest_questions_quest_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.quest_questions_old
    ADD CONSTRAINT quest_questions_quest_id_fkey FOREIGN KEY (quest_id) REFERENCES public.quests(id) ON DELETE CASCADE;
 [   ALTER TABLE ONLY public.quest_questions_old DROP CONSTRAINT quest_questions_quest_id_fkey;
       public               rewardrush_user    false    3461    220    218                       2606    18707 .   quest_questions quest_questions_quest_id_fkey1    FK CONSTRAINT     �   ALTER TABLE ONLY public.quest_questions
    ADD CONSTRAINT quest_questions_quest_id_fkey1 FOREIGN KEY (quest_id) REFERENCES public.quests(id) ON DELETE CASCADE;
 X   ALTER TABLE ONLY public.quest_questions DROP CONSTRAINT quest_questions_quest_id_fkey1;
       public               rewardrush_user    false    279    3461    218                       2606    18579 4   referral_earnings referral_earnings_referral_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.referral_earnings
    ADD CONSTRAINT referral_earnings_referral_id_fkey FOREIGN KEY (referral_id) REFERENCES public.referrals(id) ON DELETE CASCADE;
 ^   ALTER TABLE ONLY public.referral_earnings DROP CONSTRAINT referral_earnings_referral_id_fkey;
       public               rewardrush_user    false    3536    267    269                       2606    18574 0   referral_earnings referral_earnings_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.referral_earnings
    ADD CONSTRAINT referral_earnings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 Z   ALTER TABLE ONLY public.referral_earnings DROP CONSTRAINT referral_earnings_user_id_fkey;
       public               rewardrush_user    false    3453    269    216                        2606    18561 !   referrals referrals_quest_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT referrals_quest_id_fkey FOREIGN KEY (quest_id) REFERENCES public.quests(id) ON DELETE SET NULL;
 K   ALTER TABLE ONLY public.referrals DROP CONSTRAINT referrals_quest_id_fkey;
       public               rewardrush_user    false    3461    267    218                       2606    18556 $   referrals referrals_referred_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT referrals_referred_id_fkey FOREIGN KEY (referred_id) REFERENCES public.users(id) ON DELETE CASCADE;
 N   ALTER TABLE ONLY public.referrals DROP CONSTRAINT referrals_referred_id_fkey;
       public               rewardrush_user    false    3453    267    216                       2606    18551 $   referrals referrals_referrer_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT referrals_referrer_id_fkey FOREIGN KEY (referrer_id) REFERENCES public.users(id) ON DELETE CASCADE;
 N   ALTER TABLE ONLY public.referrals DROP CONSTRAINT referrals_referrer_id_fkey;
       public               rewardrush_user    false    267    216    3453            �           2606    18319 0   skill_expert_map skill_expert_map_expert_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.skill_expert_map
    ADD CONSTRAINT skill_expert_map_expert_id_fkey FOREIGN KEY (expert_id) REFERENCES public.education_experts(id) ON DELETE CASCADE;
 Z   ALTER TABLE ONLY public.skill_expert_map DROP CONSTRAINT skill_expert_map_expert_id_fkey;
       public               rewardrush_user    false    253    252    3512            �           2606    18314 /   skill_expert_map skill_expert_map_skill_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.skill_expert_map
    ADD CONSTRAINT skill_expert_map_skill_id_fkey FOREIGN KEY (skill_id) REFERENCES public.education_skills(id) ON DELETE CASCADE;
 Y   ALTER TABLE ONLY public.skill_expert_map DROP CONSTRAINT skill_expert_map_skill_id_fkey;
       public               rewardrush_user    false    253    249    3506            �           2606    18424 ?   study_group_invitations study_group_invitations_invitee_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.study_group_invitations
    ADD CONSTRAINT study_group_invitations_invitee_id_fkey FOREIGN KEY (invitee_id) REFERENCES public.users(id);
 i   ALTER TABLE ONLY public.study_group_invitations DROP CONSTRAINT study_group_invitations_invitee_id_fkey;
       public               rewardrush_user    false    216    3453    263            �           2606    18419 ?   study_group_invitations study_group_invitations_inviter_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.study_group_invitations
    ADD CONSTRAINT study_group_invitations_inviter_id_fkey FOREIGN KEY (inviter_id) REFERENCES public.users(id);
 i   ALTER TABLE ONLY public.study_group_invitations DROP CONSTRAINT study_group_invitations_inviter_id_fkey;
       public               rewardrush_user    false    216    263    3453            �           2606    18414 C   study_group_invitations study_group_invitations_study_group_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.study_group_invitations
    ADD CONSTRAINT study_group_invitations_study_group_id_fkey FOREIGN KEY (study_group_id) REFERENCES public.study_groups(id);
 m   ALTER TABLE ONLY public.study_group_invitations DROP CONSTRAINT study_group_invitations_study_group_id_fkey;
       public               rewardrush_user    false    261    3524    263            �           2606    18398 )   study_groups study_groups_creator_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.study_groups
    ADD CONSTRAINT study_groups_creator_id_fkey FOREIGN KEY (creator_id) REFERENCES public.users(id);
 S   ALTER TABLE ONLY public.study_groups DROP CONSTRAINT study_groups_creator_id_fkey;
       public               rewardrush_user    false    3453    261    216            �           2606    18350 2   study_plan_days study_plan_days_study_plan_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.study_plan_days
    ADD CONSTRAINT study_plan_days_study_plan_id_fkey FOREIGN KEY (study_plan_id) REFERENCES public.study_plans(id) ON DELETE CASCADE;
 \   ALTER TABLE ONLY public.study_plan_days DROP CONSTRAINT study_plan_days_study_plan_id_fkey;
       public               rewardrush_user    false    256    3516    255            �           2606    18340 %   study_plans study_plans_skill_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.study_plans
    ADD CONSTRAINT study_plans_skill_id_fkey FOREIGN KEY (skill_id) REFERENCES public.education_skills(id) ON DELETE CASCADE;
 O   ALTER TABLE ONLY public.study_plans DROP CONSTRAINT study_plans_skill_id_fkey;
       public               rewardrush_user    false    3506    249    255            �           2606    18335 $   study_plans study_plans_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.study_plans
    ADD CONSTRAINT study_plans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 N   ALTER TABLE ONLY public.study_plans DROP CONSTRAINT study_plans_user_id_fkey;
       public               rewardrush_user    false    255    216    3453            �           2606    18380 &   team_members team_members_team_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.team_members
    ADD CONSTRAINT team_members_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;
 P   ALTER TABLE ONLY public.team_members DROP CONSTRAINT team_members_team_id_fkey;
       public               rewardrush_user    false    3520    259    258            �           2606    18385 &   team_members team_members_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.team_members
    ADD CONSTRAINT team_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 P   ALTER TABLE ONLY public.team_members DROP CONSTRAINT team_members_user_id_fkey;
       public               rewardrush_user    false    3453    259    216            �           2606    18368    teams teams_creator_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.teams
    ADD CONSTRAINT teams_creator_id_fkey FOREIGN KEY (creator_id) REFERENCES public.users(id) ON DELETE CASCADE;
 E   ALTER TABLE ONLY public.teams DROP CONSTRAINT teams_creator_id_fkey;
       public               rewardrush_user    false    258    3453    216            �           2606    18363    teams teams_skill_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.teams
    ADD CONSTRAINT teams_skill_id_fkey FOREIGN KEY (skill_id) REFERENCES public.education_skills(id) ON DELETE CASCADE;
 C   ALTER TABLE ONLY public.teams DROP CONSTRAINT teams_skill_id_fkey;
       public               rewardrush_user    false    258    3506    249            �           2606    17199 (   user_activity user_activity_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.user_activity
    ADD CONSTRAINT user_activity_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 R   ALTER TABLE ONLY public.user_activity DROP CONSTRAINT user_activity_user_id_fkey;
       public               rewardrush_user    false    216    241    3453                       2606    18606 #   user_jobs user_jobs_program_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.user_jobs
    ADD CONSTRAINT user_jobs_program_id_fkey FOREIGN KEY (program_id) REFERENCES public.affiliate_programs(id) ON DELETE CASCADE;
 M   ALTER TABLE ONLY public.user_jobs DROP CONSTRAINT user_jobs_program_id_fkey;
       public               rewardrush_user    false    271    224    3470                       2606    18601     user_jobs user_jobs_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.user_jobs
    ADD CONSTRAINT user_jobs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 J   ALTER TABLE ONLY public.user_jobs DROP CONSTRAINT user_jobs_user_id_fkey;
       public               rewardrush_user    false    271    3453    216            �           2606    18297 >   user_material_progress user_material_progress_material_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.user_material_progress
    ADD CONSTRAINT user_material_progress_material_id_fkey FOREIGN KEY (material_id) REFERENCES public.education_materials(id) ON DELETE CASCADE;
 h   ALTER TABLE ONLY public.user_material_progress DROP CONSTRAINT user_material_progress_material_id_fkey;
       public               rewardrush_user    false    251    3508    250            �           2606    18292 :   user_material_progress user_material_progress_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.user_material_progress
    ADD CONSTRAINT user_material_progress_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 d   ALTER TABLE ONLY public.user_material_progress DROP CONSTRAINT user_material_progress_user_id_fkey;
       public               rewardrush_user    false    251    3453    216            �           2606    17052 %   user_quests user_quests_quest_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.user_quests
    ADD CONSTRAINT user_quests_quest_id_fkey FOREIGN KEY (quest_id) REFERENCES public.quests(id) ON DELETE CASCADE;
 O   ALTER TABLE ONLY public.user_quests DROP CONSTRAINT user_quests_quest_id_fkey;
       public               rewardrush_user    false    3461    222    218            �           2606    17047 $   user_quests user_quests_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.user_quests
    ADD CONSTRAINT user_quests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 N   ALTER TABLE ONLY public.user_quests DROP CONSTRAINT user_quests_user_id_fkey;
       public               rewardrush_user    false    222    3453    216            �           826    16391     DEFAULT PRIVILEGES FOR SEQUENCES    DEFAULT ACL     V   ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT ALL ON SEQUENCES TO rewardrush_user;
                        postgres    false            �           826    16393    DEFAULT PRIVILEGES FOR TYPES    DEFAULT ACL     R   ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT ALL ON TYPES TO rewardrush_user;
                        postgres    false            �           826    16392     DEFAULT PRIVILEGES FOR FUNCTIONS    DEFAULT ACL     V   ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT ALL ON FUNCTIONS TO rewardrush_user;
                        postgres    false            �           826    16390    DEFAULT PRIVILEGES FOR TABLES    DEFAULT ACL     �   ALTER DEFAULT PRIVILEGES FOR ROLE postgres GRANT SELECT,INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,UPDATE ON TABLES TO rewardrush_user;
                        postgres    false            �      x������ � �      �      x��[�rG�}��"C�Ӓ�	��L/�4��%�-R��/�����\(���>�ܛ�Um�D8�)�*���{�K�-ͧz��vI����$�mgޖm����k���7I���l��d�ۻrkJ{c��T�����ꦵ��_:[��*W��]�mޒ7�&)3�66�Id�9���X�������p�9i�I���l�Z\4UQa�\Tت��>O��|�L�y���r��x��}!����ޤ�K���{ٶ��\�������*�wr�M��X��_�<�:i-��tE�coޟk����X�]u����P�8�L�W�;/��*�������T�2�{8��/-v]W��|���^��QVݔy�d���0�����W_G%���k��2o(7���e�@��bQ�Vt���$��W��.���iU��j�����2�w)5�T�vgpeH�t���䮼^����x��L SoA]�k��f�佝�4�IF�;:��;�\A�I�C�UPy�7�;P�o�v��\z�g]g��୆;��`�TX}���V��yE=�k���d��U}�-������w��[��Kq� ��c?�jzHs����7�}��~�m�ronnV�~�#Ϊ�,�U�w㺝9�%��+s���b�wۯ۴q5�d��cm�goq����o���!q��] �$Mm+@�PxQe6�����` xkڪ�Ui�&k�>1j��{lo�ǡp��kiq�e_�f������)�b=�����_☓{�-/6��d�q����=�H+����t�TY�v���&���G﫲���K��`juⲩ�i�
X�*j�9�rt��NR+@p��r�n4�
�H�L���ݬq|��j�U>Wy_���y�J>}e�9��_�P�g�` �f:�����m�i0�Il\��6��P�P)֡^�y{��yM$Sa�ksq�M���
�4�E�57�Jl���ح,�[��W������mُ����~�d��RERL�Xе��]���<�Ɨ��,iw�
�� �,;��D���e�l�xA�X�B���p��S^�v�S>�y�����5|{l�kי��}�'�`*�*��MD���m`���Y�k�#�#k���h��Aq��ی�L�q���*ZDlV�K�=���=ێ�m���3���.��xנH�1A������M�\{��6 �ً�&�q�,-y y$��;���~��Z�&+v0�n��kG�i\{=*�<.�u�>s��T�bk�[����<f���w�6�W w0�t��#(�D��h�5S��VN}��q��E�P���Y!B�`�w����$�J�:� �A�� �щD�#����MyA�
j���E���wb���:�q���U�0��(̎QiB��EP+ZV��۟ޚ4)5��9~���|s��Ot�U��������g8>!��f}aD��8˵���s�pV����'! ���1�F�D�.�ow�(�%�Ux�/����]o�Fd��mV9� \{tU������=��>pQI����DPE�l�D7�q~�$U�����8�(iCp�oDų�!;d_VA�d������y�Wk\�U��8��m�3Cc����m�{�N^aOw��+����y�.
�s����,'��@�FLGOpt���k�-���v�-�B�_~��IQ�
ٿj�*�SF<�h]�8x+�7?�rnU�����,�����Ln �#�Fi BYtc�}.��ဦ����F���O��+��Xϑ�Ϫ����,qH?J��ow ���c{go����!7I��U7"��������zh�,p���Y6z�2�5�O�&$�=���y_�����v	qG�������QL.z�ukdL���z^�Z��
�^.��킹���d�Q����������q�	����zl�ͮ��U%�JtOo�6�
h!�q�KH1�	E�/~�y�^#�9� ��6s�'�>�&��Dt�m�:�l�y�٩Y�����Ux�֯ y�R4%��4��iֆ��й�A>o@_�U�����_�$�#���3<��TE���VK�z��.�j����kh�?P
}O|>�W}8Oq�j��$���D�2�4ȕ�=�ol^�֔��1�˦U{��� ��ަϽ��=�O�EX~k(���V��,Ut�j\9��Z����8��H}���aP�`N��Е������~md,t�tA�����"o �L�2@L�������c��e��oT��L�,���Ҽ�����+�H�4�5݇pE]5��Wp�I�N"�Q5��#���P��R��\a=]���)+��԰!�H ����H�@���.B�"T��$���N���Z��+�h��}B�
f`,�=k�m�}�j��hl�@�`�Z�NN?����4��a$SB��ɕ�5p���%>y�HՊf��T��Sù�j5g7Obъ9� ���Ԇ�3�F
��Q�^�⬪�I�A�|��80�|'�.�.�=��I���^���[��x�Ղ�r�)G��aQ���ip����#p�yM��%�{�h�*e�)Ƨ)}�_��G[��Xӧ˥>s	��qM��q��2ё��4.��嵈���y��+]�O��z�4Y�o�:H u��^x�Q1Lk�T�엄�νs�`���k�S�y�O���ߏ ��ۡȇ��WUm��3�Bz�	���EpHw��"B�Z���3!�N�٨I���E�>y<d>41=.�W�-���\N�����jӬ'\˖�d+��(�Y��"qm�fF�SX87J`�\�\S"-�ZM�S��)_����.�%��*ͪ&D+dM��H�c���)e˕:I�=�d=��̷g�F�k\��'������R>�p\�㋪`�G�:o3������[3H�_P7��� /f��������`�	�r�tSI1�0�UW����,���P�k����6�Ɗ �����I��%3cvO\��Q�t�x����� ����x[K��r�TZ�!?�v)��'����u�9�_����n�r�ƪjȉ\Q��)s�B��1������~�^�ow�y|�� ��C_2`������}$�4A�}<1�ԃ��'i�DU(K�B c���+���j#�蒭���2��C�|�c�HӐ��!�����Z�����Z8TJ
�Ӆ�GβZ\�6��-�R
�Jk��<%y����8�ov#5a����w��=hi�&#d� L�C�Mv�n�}���*��
fC�d_e�j<Y*��p1����M��tgn��-;P	�H�� �s��4d~��;X��'��4ͷMR����h�ϮM$i9�__���Q"�pZ�#��������L���K���,iz¨��?*h^�[��1���n��=ā��1m{���]$��!{�׹K�Аh�ѕ ��g)A�R
�j`#8�$�p�;5��-z��|/��<��3�D����t��D?�
��)*���2�+�fhm��}�v$j-�0��H�GA����w�\��'�����GQe�q��ƪ��eO�h����7U�W7�h��8VNb,҇����4~kx"q
�d���l,�PI^�v&NM��k�)���"Mj�Pu�Y�rz� bxW-F�*�摺鹖�����,Q9�0@yڻ��l�6���C��)��^���}T��P5ۤ�_�S�unS���v}M�5x�D2^i�� i�'R7�W ͵�ZE�L"ك.@1��5:���&��7x�:tNֳo����_l$^6F!?��3ʫ$��hz^��B�F�&Q;@��s޽\�N�An�½�	����E%G��=�9囪U-�)}��/�B���ʨ��#r���w4�D�WC*v�{��'��	�@�ˮZz�W%p�V3�!Z��o%��F̐�k��8��az�m��)��z��1��y���������|�ay�(�&�K��B�·B�Y�{�$4.N�xG!P�$Xe}��g+��Qw>}R��S[*�6
�~a g��#���C!G/7ʐ�b)����:2���UU^ �V�1^�33WR6��6�|�~pe��_�]%4"������(4����d� ?  �l���H�>V1���q#�����^R�V�5�P5A񛀯쪌�����rA�G�X��)�xVEy)57�j0�ԑ-���"���O;��4Ʉ�q:�z(aV�Ogt��t�8���%�\�f���5����t�d�U]u+��}�!,���X��su6�IhСÎĢj>a#�Y9�t�z#*�&�;|J������L��Ix�x�����C��A�{.�}Mm[0(j!qx^;.��0)3�ʎ��d-uT;�����t vVr1�y5��vC��]!�{��3�=j�090WU��T��u#�_��^��F��H���k�89�P'e˩�2�f�F$=Ǩ�VXK쓸��>�薪ـ��ގ�;�k9:�2L����KW�� ��(�c �Uyf��$'��_�a�̧@Y���$�[���x���\����ٌF��/l͢���^kS�63}t.Y�ܘKo��L}Iv�m������6.�T;�����\�\�[��3�:uϰ�6�m6I���!�k��2eAR\5(���J�w�JlN��4�ҩ�jǕfptV�|��%�,�����ɉax�ҫ�J�js�!�N�^��ϓo�*�MFqD������� �)�U�B��H�qUn�P	�5�2b1L!������X6�� ϙW�v	�*�w�	�b�aj�#���]���$��ƒO����U���ݠod�V��B^��Օ�De�������T�t�Mo�1B"qǹ�	c^�:#�=��v��3x��U�a�Qf��a��S�{��Ι��N�U�)�c��iK�wx�˯��c³�mDZ=�	x�~�dɵ���m��!�ᰛN��ڏ,g�p^]��$`;��O.���s��Gf�%�sR�g�������f�?O�}Kʲ��5_�T��5�4���6$.�%�0TcR�ʺD4SE3���CW�����^�QsnJ0}a7��=Vpr�0�蕓�P,��D�wC�����^B��-���a���Veڒw ��C"b��@�-&�	]�Eg!�D���ZI�Ѽ3ќy|'��ZS0��N}�=U�J�W�n�-�ϟ<���`��x%��Ig(��l�¿S���(�)�$N,���	�Q�?O�8"юmg�x�oq"����
IBF��}��7��(0O���	jכp�mЏ,s���7��D�MX���is��,l«�<�qc�j��TR�cM,5J�ޝ�P�OS�]�}z:��U�}���eM��1��t�ED�>�?���V�YM���;6%��O:5��`j�"4���N�Lx�MG��H�OR/�0��Ḇ��~yd@�Z���ʠڰ|�`�_R�	jh�{���eF��Y9
:\�����c����|4��xy �x匠�������a��K|�dN��W��oUk��H���h�E���_�$Y�,~j�T,��Wǹ��/_}0*G�ڇ����?MeM�v�ce�ϔ[��K�̡m�sz̻���M��X�� >���}�ukCG����vrj?��fp��2N�!el��	�Lz��������΁gkX��|!�#�����+�,�M+ɷ��ř����0���1Ix�N�!��V�<M2k;q��t����	�� �oCyu��R��'C��~Y�(F#C�ͷ�m(����Sl���ѭ�-�I=����?\��eK�b�DF�Y��l#$(�=�F� �V���`�yï����_�x)�HL<$��X�?�K_5H߰�Vǃ�h+�wmi!���3�ᵭ�MR�\j�]t�G�jXe�ұ��4��� ��%NB����FrR���I�Q�����<�4a�k��>��_��:�#s�\n�$���W_}���Z�9      �      x������ � �      �      x������ � �      �   �   x�]���0 g�+�H��K)S��,Vj��S�������tk�FZ�bM�I���a��J~���Ϭ�0+�Mϣз�A+N�[Q�8�:�CS�(�T��a���b��:��#4d�z��xo�\����;�x[!���=
      �   �  x���Ko�8��ԯ�jv���_���hҙ�i�GP0�%�b,�*I�u}/iɖl51�"�$���tIyȃ��\K���o$-�+��"G_x�J�.�߽�z�v7��匹��z,������P]��i<_���2�]��Qbn��e���	�3�x����Ee[#��!�����1J�Hх�<JY+��O����lEd+"7eӌ嚦�\E�#���U/.z��M��y^#2�*$KX��
�
��"?�獲�@� �˨�'Rd���(���Hv枱��ss�{�N�ؖ��G�
��B�H��4�aA!E��n1�2u�2�hj�S|	.Smg��\'PCy&5j>CQ��Z͚l=�G��2�X��+���2e`�P"�)��b;�!�%\g�̮_�,+s�7xZ�4TN�n�|C�?.ć�v଴��-8Sx.$�U��Q�sf�ښ�s�B����t��&�[XtC�k��d/&S�4y�4)S��e����p��T0LR��3(�����J�˙�\g3h���L9��XȜ��h6G0&����4w5n�d�s��Gv�3�Dgs��${�si|a�3A�~�)�g1��q��I`Nfߖ��7�w���s�	FmM2k���u�>���!�\2m��*��$�rb�d''���}?�(����O��S#�e�˨P�w+rVׄĦ��{C���OQR�mҷ��+�С�M_˻��@A�[p6u[+b�� x�wĞg�{�/8/��f�~yv�,�O��[yх]$�����+��>�v�,!d�wY��Uo��5�*e��ZI�"�3��C�8��g��� ���p��qc"�q|����	�*�DZh�c<��9�Y4��aXaG5m$��T\�`��󑬬���\��� 0��
NJ��N(�:9	�O���O.�	O:�+��u �12w���[�T�%yH�收W�ICLj1��r�'��䋪�C2�&��E�iG��nj[�ݿ'0�r�%����/"g�"���6r�A*��"�O���|�j7�p;�f �=4�n��5�����ػ���/o=9PG�Eb�=��!�ڦ2����S�4���}�$/�k�����@������A
�gY��`��ɠ?��v�:p	��,���a�!z �[�}�wm*ԋح����zh��5���������V���C��NG��r�<�#�4����G�s0�|���� �m�f��B��"sy'b�>���؞�x��32���ZF>28,஗��q0�Ѓ�QǑ�u,*���N�� q���8���
�4�E�(�հ���u,W\C1����u�����46�LS�J�@�Zӊ��I�}�'�~w�B��_L�����ms�LY��>}d>�Y���`i����5Mb��^[��[��������*�9s-�N�A��SIc�IR��:��69��H]l��_w�
ǖ����.h��Z�/�d��&��E]�y���u�'�      �   Q  x��V]o7|����ٲ,�P���I�ƈ����ÊGݱ��'Y)��;�;�B ��7	������r(޲Ut������/t���-�{'�����D*�k��R�ǧ��2��l܆�@L���娨��������h�R��ǯ�����o�����4/u,�k�?�tS��'廓,��-꠭
A���d�w Z$��fߨE�Q�%��Q�����ژ��r���ʸJ��6��6i� ���(B*�2ZrD?:9j�{��Ŭ�fKS����j�i�q�^���(���h���JI�FA���Q�؆��ppcq�^ց���b>{G�(Ğ���.6�z����l��ܻM,(��yA m�Ǎ�(u/������L�Χ�.e�;pd�c�yo�����
��l�y�Qh�$�C�]��s�����@ܠ��Ih.�����a�� J�HF���sH��H����Kq�����-M���"��y�ВjbR�i	Ee��������;�ר� 91�ڕ�Ig��,���
q�����<o�ޡװ�Qд��֥r{\��⵲4ɸ�Υ���4�Ϙ�E����z�u*!��r�v*[ؼ�=�P��0N���<'��zO&ۧʗ]`kPQ��eeT	QQ������A���[��o�wOS�W/�ʞ��Br��	�Ȱ�Ջ�V
�dA�w*�h�H�	�P�0�w0y`r�Fؘ��G����s~�N��l ١Ăc��F��_@�?;.h�f����`�����^��%�Tʛ��aTIY��6�����p�n�X�j.�A�ସwБ�]��~*�W�!���4�k�\���	�^��:�%�a�q�����a4jA�s�b���isZ
�-"�1��rX��V�!����Xf�i�Y-���=��aZ����S�
��a�č3t\���qu�O�R���X����=u����.xwfj�?׊�Tm.KmJXqF9�����3(�ҭڠ5�k�_FEP��Lo�X�IY�,�N�ZF{D�$�'y��#�T�
�z`�B&^� 1p��'�F��gxԀ�S%��szE`�(���8�[�ϴ��v~���L      �   f  x���Iw�H��ħЩoviK-s��c\`w�{sIK	d[(5Z�b>�DJH�*��P��DF����lr�myt��o��cZ��(�q߼��1�;��mYf�?�|a?�.K�u$v_��[�tA3Z�,���X�3Q�r��4�.�&o�xL��(sZ��X�[��i��5�؊*�)��˽�-��Ը�i�1KK^����zt�Ob�zϘ�"bEk�c���L"�=�{X0���I}�_\�i�"f��<��G��%�--xt4h�F��Z�W^�$��[��w�oy`-��I�x~1]����c{�!��Oᅟ��r+�ڬ?�^����B��I�7���Վ��L��d9�n<TiLw49�rh[`�=��Blfܤ4ٗx�N:�m���Y+"Nc�bN�Y��a�����.�^wQ��=Ј�	�n��#<��@o�k�pZ�3K��J<; ;��%􉌗��D�!8��WE�Y��������lr�J�*y�	E�pFS�U	�@������=�U$9����<e�������CdO%��1�j�vK�>�*ǘ{f���u#���	T�L�e��TR?y�Ŵ�U��Ub,E�i�����J��9������c���^_�!��0��h��l�Y�d��[��Z�:�H�t'�5XWݜƧ����M��o��cڼ��}�iz��������z��vZ�pغ�A��ξ/Y�Ժa��j�m�43 7�P��x���)�oŴ�)bO�\��'�j���Ma�RH��<��?��2��'t/��@ܾ�X����ۑ~�����_iZ��ݖ�x}��E"�T+��Q��ҭuǊѝ�����ڲ#�c��i�
�g�`HK$]}�m�e����Mҳ�s.Q9]ל;������?0]��9����u��*U�Iz<���D�u�������O����//�9U��~��eva�ty�	��Zۂa�e�e���w�A���7m��l���6?T�G��p�/.�7���#ȫ�GM�EM�5ɶ�lG,��{�|Zh�!��Q�2�E��V���(�>Q@�0i��'���b�Y�}�� e������N0��?P��2gLe~���y� �P�]������v�k���@W�Q�M��eY��Vn(�����������nc���Qc�@�^�Q�!��=�8������6�w�O�m3�.�?��/?��=����=�]m�V��0ٹn��T��bm��z��Z'���$��Ss�d~׭@�e�p���!YZ:
vv��������&����CBWA�؏���xZn���p��.��«���D��v��Wz
Q�I{<��`C�������#^��!��z�B�)m�5e�)�F�R����Ta�ڔ��ȌiQ�ژuI�ն�o�ٓ�q�\���-F9�)�C��oQ�=�S�-X_�q4h�`�-�e��w��&�F���[[4��lg��{N�Qw�pl���(O�-���D�1F��l��T�1�ߍ���Ü1Z4�c��Z��1�q�@�Zy�EE��f�W3Z⅖	S�� ���|h�N��E�ʤ(��@K*)햰g�Dt���5U�, �ΒZ��\\�3d�1�c���1�ʵ�%�mH�Л�ZW���F���]���w�8�lG���j��@��U���I��z@E�4~�@&&�o>��OK�p�݈�#���O�����(���{���1���`X��;ۊD��.�J�g�N��&���1�U�aǫ<l
�œ���}��ln�1���\El�4�Ͼ�ߛo+����P�g��^�nѨ�zMp�#��|�]P����>��R+v#B���.���H�C�.�Ι���G-�r��\K���{_�	���p�f�b��a��4��O:.�m�]��L�zu^���Ys����W�Or9ь)���E'|S��m�Ϲ��O&v��)�he�!��w��й����\�orl��l�&��pJ@ �/����vͫ�PZ88~;6�B�|��?�o�i�QG�CB[�O�-g��Fc�8�!$*��xI?1�on�;d��8N��Uϸ�o���wL�r�h����kA<�4��H���:���k �?��m�      �   r  x�U��n�0�����Y�.;\M1X���b7�L�Zt�$�Y�~��t�Ml?�?I���趧dF�>��50��팖�I�K�-��z�V01Ex4iA:8�x��M�W0�ࠋ�{�G� _?���*e����>V�$I�3��~�U��χ���N�%Ô� �9��R���*0鈬�Mӛ�0��a<gƾf��Y��b��W��~��I��xJ��O�p��J~�6R�Qo�(F�6iC^��K kp9a�v6��u���V��ሚ�x1h�T GN��qU�k׻ܟy
b��)�r�"�[��n�V�`�S�]J�nv��ҬY��5�C4��;�Z�.}��6�$�fq��H�<���K�R+�1�#Q��n�[��Z#喦Ek�T=�Gc�H~�qqb����\-O�g�ޞb�v[c��I��gc[������䭺�80�q��2f�(S��#�Z� ��ф%�l�%vY�8�y+�����K;�QD5,k!4�y��L�x_�̧���lLΝ����4N&M�bN��=�p�/�����z��2=kX�[�Ѱ�J�28�6W.՛�in��ɶ�	P7{8\�/���T�ͻ��_�✮H9T
���(J�Ȣ7�|6��M�4b��      �   �   x����N�@D뽯؊2�I�HH; ���)h�ce�r���k��"�6����Kaoa	��sq-+9�V�n�����V�%iv}�]s�B?J��,aۀu��BI�uO���a���F��YA��/�!ȟ�
��BÁHf(+x�#�5�Vl�"���H94�8�8�_�D�ǳɠ��s�ɍ�:��L�'d����/�PwV�T�S��w�8wi�+fE+<��s��;��c
:?g�c�ua���e��      �   5   x���  �7L��HJEgq�9�sq�K� !�rx5�]�Fخ��3U���O      �   �   x�}α�0D�Z��}`��E�Cdי �#Q
�1\��qZԊ��Yʫ�wĮc3KCZ*��P��z�������~�5���3o'��<Hw1�������c�~�_|n����I�al�Rk� ��4}      �      x������ � �      �   /   x�KN��4�J��\)@�L�q%f����s#���	W� (�      �   �   x��ν�0����)��0����G�
'6���%��-�	;]s�]�gPPF����|�ԏԊJY�BV�� W��MI��x��%���y�����\$W���R>�Q�	�����p��%�:A���_�n 1i�@���Υ�����>���1��MQ�,��oKD|��      �   �  x�m��n�0���S���!kZ,�zi�]���ʢ����ӏ��[v�-��Ǐ��f��L�	:���z��g3�8y2_��- X
9�w���-�.�%��q�4PH/����Rt���}�"��Ȗ����$�r�$�,5�+��|�{����V��@6�[eO�`_���؎85����=%��iJzg�k}�C�F��sݕ`��~��	<�R��R������g��3�}2}$
�az���B����qP28y�/r��n5)<lK��iĘ�9Ͷ9-8����mb��F��jWY��_4ԧ���:"M>i�NfV�| �D�oYvW���m�7}5�:+����q���ٜ|!sЕqAX4��Q���1��Y��!���_���;��XO|�(-�4ygQG�.�f#f;��j��~�Z�4��,�.�C�:h��-y���yŮ4�NYP_h��SR�e�jL�j�'�󑪩~6UU��%;      �      x������ � �      �   �  x��VMo7=�~�C{��Ɩ�z	�jԉ+�(�ĊKnI�d���RrU;����f�͛��3�+��_ݚ�C5sZQ�O�5Q;�?����Vy��Jq#��+��ȋ��U�??�;�S��F��L��#���U��8��WTj)F��$��ꯖ���>"c��LF���3�׵�+1!K���U��N�GZJ_~l�LT΋���o9�rޓ�_�������7�{�k�ȖT��'�.�X����b�|^��[
�ZS
),-E$5!J� i�[N3,�:���	�F�ר��9'�^�7pY�W|�~4N�8�.D�ڊw^�Sz�5�51�|rw�������F"��A�d(� ��uzC�� OzjE)��4���`n��
A���R�c7'�j�����*�/2[p��XD0$��NJ4z�@�@��c�3�F+4��"S�� s�<��Kkϣ ;��f�Cm�V9\dja3�8+�!�2s�%���^�#)���T�i�V
�(��v>V�hǇj�>=�4l_|+�4���ly<pf�V��z����jS�w�,�)~� ��HP�1
�r�9��$� �G��b=�����%L]�&�/-d�@H�_sƓb�I�FN�Y��BI��ή�^H�z��t�{M��9�P�+□J]�P'�3B9,o�hb���xb���q�h�O�}��T;�};HVMf�9���ރ3f�r�2���~\��_�]�yJ�o���h�b����xB��iB"��� .�0�tUA,Py�2�����N��:"&c���s�<S/�4��,>7�B�Z����H��׏�ʩ6����j�/;�ô)X ���@�⾘Uz�R�Pl����DӰ8��"��:{�d�zi�8��*��i���*D(�w�&�6X!���9a+�@| �]�$�r���(��<A�v���2,����⸓�O����Y,�����C��o$��cL����o\�k��iZ���4tc6k����{��0u�l���/s���$'h8/b����u�s�ۗV��U���8>.N:9>hK޽v����pEL�gWI�;�XP0vΈwk��9^��%W坖��=k�E�����s3Ӷ���ON�v^aO@tDK��RL(� �^�z�=��      �   ?  x��U�r7<c�bJ�ȥ��>��T\�E��R�:��C.JX�
���S~#��/���([�T�����@O�꾧�A����R�]L����1V豭ߩ�C�e����sU�6���nQ�)�Kt���8�"Lum�jjM���;|����LS���.<��;��z��:V����Fю�pif�J�O>hé���έz�.;x?�1�:�ڕr�� ��C[S�kv�j�9vPc9��C��kB^�9����m�Tw���UT�*E�<�&vYK�1hK&�'�|~�	�G���F�`Q�2�qi�iެ���e�j�#��.�P�����6J��� ��K�9׮���#��R���c���癎ى��I�-���86�É�b��Jk��hȭ��su��\���c���v����E��;t|�s�]a���qN촁�\6P�t�&f��#E��b��6��@|�*�p���̰�K��0�Wǯ�h�}k�PKhwұ�l1��m�ɉM����RDz�./
>�I��z�\:��<�3���l�v.���Y~ p��jCMk������e�ڬ��:y�R���Ƣ�Tzn])�<��-�nV��kk%�C�s9OU����O�>��Į����Y~$���G��u�t���HRoT��v�޾�����a�X1��jL�,�����%��	��ʾ]��S����㢨���F�[�L�,?�/)�*x�q��[����7��*���m��1j�����tmh���� �Ո�z�>\˱���Vm�e����	��;V,���]�mԑ���6v�66�ȶ��>�X�q!e_�dY���h�      �      x������ � �      �   r  x��T�n�0>+O����l�Vom������l���ت�ՕR�I֞�{�=�(9M]�K
0@Q��C�Q��\�;c+�,U]k[ir�k��B��P�N�`b�'v����V�خ%�ej��5ᔋ����������ԇe�x3�񙐻0�(��"��U�Tٞޯ�х*n�ƭm�L�8a��$��	�:B��*�7��T�L�^��l4y�5J]h�5�6���c�-4r������$���)P��B�X��7J��l��ֺD=$��.��uM]��Ljak�@� L �G��o�24�,Js�f��{)c2��X�L��V��p���N��n�:�l���ɡq��j��1�
x��$�b��BR���V���ȤyX����l�ڏ3	��^|���Os(n���bI�o_�sb]jO����ќ�6�U��Ȟ��v���j��n�>�ݩ�eKc���	�C��k��@���o��4���j�q�eA8FG	��]q[,��p�ZS���R������?��9X<'����v���!�����}s��-L����oZ2�9���ӎyLw}��mjq-BʎBbl I>�?T]o�pI��x��g��U�$i�C@sP< t=�F� ���s      �   b   x�mʱ�0���B}`��$%��d�9���+
$�Lh���N�p������|���S����3'��z��̞!��#�	�d�NF��_c�        �      x������ � �      �   }   x���1�0��9E���߱�Ƈ�	X��N P��U�������m�s��߅^���>�IXl�:@����p*��������ճ%��k�����Z��$�R�Y�JwB��%�������^�B�*;<      �   �   x�m�K�0D��]���{6Ql��&����I+X��y�G�E�#����B��A	& {+����rԓtz�S�Ys�Z@�\�7$����`� 	��~�*`^LL�^[r�P��G���|.����0�!���K�&�-�mM�S>n&rH��NXJ��#t�lY�� o`�s      �     x�}�Mj�0�s�ٗ1��,���2	e��Y���V�)ă���ߓ0a�~���������v��~E�����B��=��:8'�xν)g2��%�<�������#�@Zc�\/�%��}}���~4�h:�MKVt(6t��M��=��#�״n���>��48B������ĳS�sD1����EW��S��P�0�1I������^X����ع�&����/�����J=�X����7�����u��ץn1�ϼ,�J���      �   �   x�m��� ����d�e��,^�B*�?�6��-zjk2��ɠ���9�L� a��� \�-�j\�@�ͩ�|CdҞ�x� m��iU塞�j�pD	5"U��T�������*��K�çw4|�AC�a5��-h��Vۍ��{�/��^:���ә�X;��w�����eO      �      x������ � �      �      x������ � �      �   �  x�}W]o�8|V~����&i���u�6��Ψ��BK+�JTI�>߯��%�$��<X_;�����qq\\W��q�z�n����>Q ��M�jӑڻ��Δ���}�W�P�J��]����H��t���]0������L�;m���*]�S4����Ç�9Fܐj��u(uO���G'����V͑��T��2^E]�#�`�NB�}��*�赉2]i�0RK(qA]��M�ȫ���bH�Uk:���L-6΅�B�D�u�^��O���I�g�mɺ��.�mo�	n�r��SȨz��.�h�V�^K�z�J��-��0SW�Z�Sk
k<,)��y0_2��g��Q*fJ�F#�SrSZ��	��lG��� �H8��cdI�KO�� �J<U�ڙ�A�଩T��Ig�Iq�����jCq�!8#�ᭆ~*U���f�7�D�Pq��	&̊ߎ���o�����㶆�S,��r*�>�^mɛ:��Vز��jhðV���/���W�Ư"�rv��C��G�Վ�/\3@��"����BJ�6�)�Q�<���)NP8��-t�k�W����f��H%j#�p�%�@���L�T�P��j���!�C��K@}����G�	����db�](�k��o�W�p0���Z�7��HYj��(��_!�¡���A_���t��Ph�$1.��ϵ�A�̀��yn�����|�Q|��F	�qqV�V��u�=�c:͢ϥ�:�;���s�5��z�{��v¥�����2L�FT���s�CL��-l-��	���Y!�N6_�vF�esL	y�_MP;���E��7a�W�~���8���;n���)�Hr��W^
Q���E�����%�Z��έ�=B�1�FZ]f��O��C.�(R���$)��Hh�kv3��Di��S2��%څ�]U\��ظ'`�sW���p�Z{n�|V�R]��������5�B�߽���d$x8
a���9b|����um�xdߘ[��w*����z\�CV��4��4�@�;�uW_N���#������4�pl�O�"\��ȃ0�����=z{�	�MqQ̍�0}�����<��\�'򆩴k���GD�tÔ:y*�)�Z�,�K`*�nM�~�g�Q��߲͗��#��L���6���D��L�6-� �8$���!���w;�Y�#=4Qn8���Vm:ǥ�A<��r���+]�=..�m��Tט���&b�Щ���0e2�����Z�[����	��az��Q'_���K��6�0>����`��H�c-0���Cʋ�PEPo	s6Jt�X�Ɵ�'maz���ɸ��T+�����`��XJ���J��Rtd�~�� ����ȡ�m�v�1Ƅ�U�I����y��@�h��<y-u�n�}�ƍ�QӃ��1�lns5^�-�!HКHf
�� i�7�{V`�}���^�Q��0��x]e2�QM��^��?�iP�e{89��w��W�޽T������}~����z�J�i[j5o��oz�Fr%�wꂡ�_Wj���Vߓ/搽���1�U�$�ϣ&�����66*��%�zS`b_y���xE,�4v
�W6kZ��&�'������ա�s���^��C���MU*v������5g"�"o���L+W�$��8��*M�<$�2���%�-��k%A��b�_��尶&�c��6/Aq��Bp=nH��NK�T�1t��e�l�(�mL���ٗ�ώ������k      �      x������ � �      �      x������ � �      �     x����n�0���S�'������-�᜛�ȥ@!�L,��Rَ�>}I
i��#'	���pfG(�hڶ�ov��!5���i��wI�zy�Ͱ��oW�3�g�!���Gm>LH�i ���6dBiaNa$�YJ��pX�S8:b(�X��L���>m3���_��=���FNg��}�^�C��٪Y���6M�M?H���ճ9�v�z4������5��Gˮ�qb������9T���'���Ƞ0������ۭ�Csh��ަC�T(9�)J����up���Ϙ:��H�M�\�"�Y������sAv*�h��x�����c�7M�ΘE��t��rz��u�[y��A~�O���"�m?$	�H����A*�q�ݸ���KL� �� D+�E��F��N.y63
GO���UJ���30���
�y��%��X;r�MT��i<����1��b��d� mkѿZ����R�����m_p5D �u��ë�5E��je�#S7� ��vև�g<_��yq�A9sm�vX����d2���-      �   �   x�����0E��W�7��>>�/ 1UP(���� &�Bw��;��PD�(ˇ��P9]o�8�g�p�ˬ�H��$o��ڞzRM�_8= LF�"�v �%Vp��� �-5�sE':���<�1��f�]������Oj���Jm�$�57r�ڠs��$P���@Yʬ �|��&]�R�1~dmd(      �   M   x�m̱�0�:�"=����1�,�?���tޒ�`>��D1�K�[F�xK�![w.`>��i؍5��"O�KE�i0      �     x�]��m1г\����Z��� ���a8�0t`�?9��֌֤��/懌�0�@S!�e]9�k��~��H��P�cl�_Ο� �)rf�8I��r�P�T�$V��(E���D�69�K�nD�bprj@n}�K��%N����
����{����6���VW���C�A���l���"��d����]Is��\fwe[醤	փl�?�6��:���'�Ԙox�b%�J�#`�ޣ���l+R������}u�Y�5�nu����x� �p      �   I  x��W�r��]���E��mQ�R��� 0Oћ�T����%n����D(�Bd婓yN
"��]�jg�����c���;r�C�
D�G�F�^��{K��ɤ���������㶗�U/N�]bt�Y��7�,]����r #(��E���@�������F �����A�XDL�N�?���}�B�+��R ���Dj��o�D%�A%%C]�r?۪���J�I0k����L,����f�v�V��"eMc'r�־;d=c|�����>��ިT� �~��5���dU(6-������o�hk �X�A#��Z��&:�TG��=�Z����|ﱦ�k699�<��EXUq���T���:���1�,e��u�uu,9�F9_Ǚ��e%�Xp��
�� b�\�A�<�� 
� ����I�%�V�0����_'�u�+�aA��$����q�;�����^�$������A�`��D4��*SA~���x�6f�Jz�����p=�G���Qak��*.����yt������� %£J2�Rΰ'|l�E6D& �Cv��u�,-�w��I�v�8G �{�	�GV��W����d�޶
��a݆o=�!���Sc�9>.	��1�n���5�*�c��tqS@��uO�X����Ⱥ����J��F�F"7�{񱼉���p�l�I���Wr۪����Q0Do�A���lj�Oc��t{�4�o�#E�gy�t])7�\~���J�
�&ם��G,zB�u�QB���2�̍U�x�'������oT�V�X�3Ǟ�ۍvZ��F�]n<�.j��qi��N�1�N?բ����Q�Z�O�(�/(�<H�vn'-���	���q���F�	5yPܸaW�?�q�����Ro�񳈖r���<C�wJ	�ݕ�6m��~��N+E [���UM>��\�B�1 ���DC���2��k�T����>�a��@X��{'��>֚��-��<ļ��'�ަ:o��`.@�[�&�uV}v�8\�~�s�@]�h�K���U �9N�}��
�Ml	˺�
�3ɒ���\x��u�A/�vQ�k��t�j�δ;��n{�Ҝ6=���\��P̫��ڮ;��ґy�O� �YA	����*�	cDɻ@�ل��ϊ�l������>����x���)-�s��U�˺l՞�r�&��n���=9��5�>Ŀ���ñ
1����f��T?�k8ڕ� ܄r��í���=�5fiP�G��.�js
ڰ>W�qb�S�?��u,�B���U��f#����,����)�俥�A�	E���U˚�4ʯ�E>����B	�	�urױ{`�G���_@�i�:I�	=�75�h��9rʍ,[6�9�vĆ�h�W��n�BX��˴�"˕���}�[��0����t�X ��1�U��E�	m��x���2<���X�m��Y�ξP@�l�<��w�%lQ�o>v��\Oʭ(l%SJk���9�ܡ�^���xW��0�p)A��wÒU�c�����'����
�&���1�u�1Vٲ �S�9s'�y����l��en�V��b�>�}�uӨ��������ˇ�Ѻ�{���X*ƥD�)@�r`���q�?c:;pA0�(q&�W_�b��U���;���<���k�)#���C�.z/X�7�e�?���q� 	h ���'z� ���[�������r�\��}�[�翉��60GCٝud73�<2;��d���|c����k�QmJ�v�^����yQ�s-�<F|����d���cR=Y螗b�(��QL�͎�߾}�?�^�x      �     x���;O�0����١���%�G�Y����7���*i\��I2 T� �|��5%� 4 d��b�PO٥2�������k�yx~$��<��H����3hk�4p͎P�2yP�
S�e����ڔٿ�S�Cq��)e⎏>y{Y���L��R2`��U���k�~{&MÔ��&4��u	e�9.s��"j�j�kp�Jm� �����:��mݺ�Jb0��e�+<��Z�{��)h.5�"
ɷ	�߉�������RNMUU��     
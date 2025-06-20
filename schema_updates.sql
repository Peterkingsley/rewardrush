-- 1. Make users.full_name NOT NULL
ALTER TABLE users
ALTER COLUMN full_name
SET NOT NULL;

-- 2. Change redeemable_codes.code to VARCHAR(16)
ALTER TABLE redeemable_codes
ALTER COLUMN code TYPE VARCHAR(16);

-- 3. Add indexes on redeemable_codes
CREATE INDEX idx_redeemable_codes_user_id ON redeemable_codes(user_id);
CREATE INDEX idx_redeemable_codes_is_used ON redeemable_codes(is_used);

-- 4. Update parse_payout function to handle null/empty inputs
CREATE OR REPLACE FUNCTION parse_payout(payout_string VARCHAR(255))
RETURNS NUMERIC AS $$
DECLARE
    match TEXT[];
BEGIN
    match TEXT[];
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
/* this script populates local developer database tables from FDW wrapped 
foreign tables, according to specified sampling logic. */

BEGIN TRANSACTION;

-- Post; take 50k for now
DELETE FROM public.post;
INSERT INTO public.post
SELECT * FROM (
    SELECT * from prod_public.post
    ORDER BY prod_public.post.indexed_at DESC
    LIMIT 50000
)
ORDER BY indexed_at ASC;

-- ModActions; take all for now
DELETE FROM public.modactions;
INSERT INTO public.modactions
SELECT * from prod_public.modactions;

-- BotActions; take all for now
DELETE FROM public.botactions;
INSERT INTO public.botactions
SELECT * from prod_public.botactions;

-- Account; take all for now
DELETE FROM public.account;
INSERT INTO public.account
SELECT * from prod_public.account;

-- SubscriptionState; take all for now
DELETE FROM public.subscriptionstate;
INSERT INTO public.subscriptionstate
SELECT * from prod_public.subscriptionstate;

-- ActivityLog; take all times Emily has viewed the feeds for now...
DELETE FROM public.activitylog;
INSERT INTO public.activitylog
SELECT * FROM (
    SELECT * from prod_public.activitylog 
    ORDER BY prod_public.activitylog.request_dt DESC
    LIMIT 50000
)
ORDER BY request_dt ASC;

/* anonymize user DIDs in activity log

start by gathering all unique user DIDs from activity log into a temporary table */
DROP TABLE IF EXISTS obfuscation_map;
CREATE TEMPORARY TABLE obfuscation_map ON COMMIT DROP
AS
SELECT DISTINCT ON (request_user_did) request_user_did
FROM public.activitylog
WHERE request_user_did != 'Unknown';

/* add a column for corresponding obfuscated did */
ALTER TABLE obfuscation_map
ADD COLUMN obfuscated_user_did varchar(255) UNIQUE;

/* fill obfuscated DID column by prepending appropriate DID identifiers to random UUIDs */
UPDATE obfuscation_map
SET obfuscated_user_did = 'did:plc:' || gen_random_uuid()
WHERE request_user_did LIKE 'did:plc:%';

UPDATE obfuscation_map
SET obfuscated_user_did = 'did:web:' || gen_random_uuid()
WHERE request_user_did LIKE 'did:web:%';

/* overwrite original DIDs in table with obfuscated DIDs (possibly is a way to do this without scripting, but I didn't find it) */
CREATE OR REPLACE FUNCTION obfuscate() RETURNS integer AS $$
DECLARE
	obfuscation_map_row obfuscation_map%ROWTYPE;
	did obfuscation_map.request_user_did%TYPE;
	obfuscated_did obfuscation_map.obfuscated_user_did%TYPE;
BEGIN
	RAISE NOTICE 'Entering obfuscation function.';

	FOR obfuscation_map_row IN
	SELECT * FROM obfuscation_map
	ORDER BY 1
	LOOP
		did = obfuscation_map_row.request_user_did;
		obfuscated_did = obfuscation_map_row.obfuscated_user_did;
		RAISE NOTICE 'replacing user DID % with obfuscated DID %', quote_ident(did), quote_ident(obfuscated_did);
		UPDATE public.activitylog
		SET request_user_did = obfuscated_did
		WHERE request_user_did = did;
	END LOOP;

	RETURN 1;
END;
$$ LANGUAGE plpgsql;

SELECT obfuscate();

-- not taking NormalizedFeedStats for now - maybe generate after the fact?

COMMIT;
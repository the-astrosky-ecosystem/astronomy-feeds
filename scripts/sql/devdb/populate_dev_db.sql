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
-- anonymize the DID of users viewing the feed (request_user_did field) here!
/*
the below code works for simple replacement, but we need to maintain the uniqueness 
of each did.
*/
--UPDATE public.activitylog
--SET request_user_did = 'did:plc:a'
--WHERE request_user_did LIKE 'did:plc:%';

-- not taking NormalizedFeedStats for now - maybe generate after the fact?

COMMIT;
import json
import random
from astrofeed_lib import DATA_DIRECTORY, logger

# DIDs
# emily.space: did:plc:jcoy7v3a2t4rcfdh6i4kza25
# astronomy.blue: did:plc:xy2zorw2ys47poflotxthlzg


# Pinned posts dict, where:
# - keys are a link to the post in ATProto format
# - values are the post weight (higher = more likely to be shown)
OTHER_PINNED_POSTS = {
    "at://did:plc:xy2zorw2ys47poflotxthlzg/app.bsky.feed.post/3mbk2b2vwoc2k": 1.0,  # Stickers at AAS
    # "at://did:plc:xy2zorw2ys47poflotxthlzg/app.bsky.feed.post/3m5xsysd6u22z": 5.0,  # New devs
    # "at://did:plc:xy2zorw2ys47poflotxthlzg/app.bsky.feed.post/3kyzye4lujs2w": 3.0,  # Signup instructions
    # "at://did:plc:xy2zorw2ys47poflotxthlzg/app.bsky.feed.post/3lbepgrmp3s2c": 1.5,  # Moderator applications 2.0
    # # "at://did:plc:jcoy7v3a2t4rcfdh6i4kza25/app.bsky.feed.post/3kkrhwzmhg22i": 1.5,  # 'Bluesky is open now'
    # "at://did:plc:xy2zorw2ys47poflotxthlzg/app.bsky.feed.post/3l3xtpvv46k24": 1.5,  # List of new feeds from Sep 12th 2024
    # "at://did:plc:xy2zorw2ys47poflotxthlzg/app.bsky.feed.post/3kyxnyimjna2a": 0.5,  # Like the feed pls
    # "at://did:plc:xy2zorw2ys47poflotxthlzg/app.bsky.feed.post/3ljiutb67z22r": 1.5,  # AstroSci
    # "at://did:plc:xy2zorw2ys47poflotxthlzg/app.bsky.feed.post/3kyxobfx76e2n": 1.5,  # Getting started guide
}


with open(DATA_DIRECTORY / "pinned_posts.json") as handle:
    DEFAULT_PINNED_POSTS = json.load(handle)


def add_pinned_post_to_feed(body, feed):
    if feed not in DEFAULT_PINNED_POSTS:
        logger.warning(f"Pinned post for feed {feed} not set.")
        return

    post = DEFAULT_PINNED_POSTS[feed]

    # Optionally randomly mix in other posts. The default post has a weight of 1.
    if len(OTHER_PINNED_POSTS) > 0:
        post = _randomly_pick_other_post(post)

    body["feed"].insert(0, {"post": post})


def _randomly_pick_other_post(post):
    return random.choices(
        population=[post] + list(OTHER_PINNED_POSTS.keys()),
        weights=[1.0] + list(OTHER_PINNED_POSTS.values()),
    )[0]

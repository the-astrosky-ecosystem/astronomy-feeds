from astrofeed_lib import config, logger


def enable_cross_origin_requests(app):
    if config.ASTROFEED_PRODUCTION:
        logger.critical(
            "Something tried to enable cross-origin requests while in production. "
            "That shouldn't be able to happen, and is a security issue. Please contact "
            "the feed administrator."  # lol I made it sound so serious
        )
        return

    # This import only triggers here just to be extra safe
    logger.warning("--- CROSS-ORIGIN REQUEST HEADER WARNING ---")
    logger.warning("Dev environment detected - enabling cross-origin requests.")
    logger.warning("DO NOT use server in production in current state!")
    logger.warning("DO NOT allow non-local connections to this server!")
    logger.warning("--- CROSS-ORIGIN REQUEST HEADER WARNING ---")
    from flask_cors import CORS

    CORS(app, origins=["http://127.0.0.1:5173"], supports_credentials=True)

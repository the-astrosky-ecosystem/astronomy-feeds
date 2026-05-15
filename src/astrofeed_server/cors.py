from astrofeed_lib import logger
from flask_cors import CORS

def enable_cross_origin_requests(app):

    logger.info("Enabling CORS only for access from " + app.config["ASTROSKY_WEBSITE"] )
    
    CORS(app, origins=[app.config["ASTROSKY_WEBSITE"]], supports_credentials=True)

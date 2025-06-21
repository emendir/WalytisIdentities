import logging
# from logging.handlers import RotatingFileHandler

# Formatter
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)

# Console handler (INFO+)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

# # File handler (DEBUG+ with rotation)
# file_handler = RotatingFileHandler(
#     'app.log', maxBytes=5*1024*1024, backupCount=5
# )
# file_handler.setLevel(logging.DEBUG)
# file_handler.setFormatter(formatter)

# # Root logger
# logger_root = logging.getLogger()
# logger_root.setLevel(logging.DEBUG)  # Global default
# logger_root.addHandler(console_handler)
# # logger_root.addHandler(file_handler)

logger_walid = logging.getLogger("Walytis_Identities")
logger_walid.setLevel(logging.DEBUG)



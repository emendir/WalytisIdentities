from datetime import datetime
import logging
import os
from logging.handlers import RotatingFileHandler

# extra in-memory recording functionality for logging.Logger objects
import emtest.log_recording  # noqa

from emtest.log_utils import get_app_log_dir

LOG_PATH = os.path.join(
    get_app_log_dir("WalytisIdentities", "Waly"), "WalytisIdentities.log"
)


class MillisecondFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created)

        result = dt.strftime(datefmt)

        # convert microseconds to milliseconds
        if datefmt[-2:] == "%f":
            result = result[:-3]

        return result


LOG_TIMESTAMP_FORMAT = "%Y-%m-%d~%H:%M:%S.%f"

# Formatter
formatter = MillisecondFormatter(
    "%(asctime)s [%(levelname)-8s] %(name)-16s | %(message)s",
    datefmt=LOG_TIMESTAMP_FORMAT,
)

# Console handler (INFO+)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)


logger_walid = logging.getLogger("WalId")
logger_walid.setLevel(logging.INFO)
logger_walid.addHandler(console_handler)

logger_dm = logging.getLogger("WalId.DM")
logger_dm.setLevel(logging.INFO)
logger_dm.addHandler(console_handler)


logger_gdm = logging.getLogger("WalId.GDM")
logger_gdm.setLevel(logging.INFO)
logger_gdm.addHandler(console_handler)

logger_ckm = logging.getLogger("WalId.GDM_CKM")
logger_ckm.setLevel(logging.INFO)
logger_ckm.addHandler(console_handler)

logger_gdm_join = logging.getLogger("WalId.GDM_Join")
logger_gdm_join.setLevel(logging.INFO)
logger_gdm_join.addHandler(console_handler)

logger_datatr = logging.getLogger("WalId.Datatr")
logger_datatr.setLevel(logging.INFO)

logger_dmws = logging.getLogger("WalId.DMWS")
logger_dmws.setLevel(logging.INFO)
logger_dmws.addHandler(console_handler)

logger_keys = logging.getLogger("WalId.KEYS")
logger_keys.setLevel(logging.INFO)
logger_keys.addHandler(console_handler)

file_handler = None
if LOG_PATH is None:
    logger_walid.info("Logging to files is disabled.")
else:
    logger_walid.info(f"Logging to {os.path.abspath(LOG_PATH)}")

    file_handler = RotatingFileHandler(
        LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger_walid.addHandler(file_handler)
    logger_dm.addHandler(file_handler)
    logger_gdm.addHandler(file_handler)
    logger_ckm.addHandler(file_handler)
    logger_gdm_join.addHandler(file_handler)
    logger_datatr.addHandler(file_handler)
    logger_dmws.addHandler(file_handler)
    logger_keys.addHandler(file_handler)
    logger_datatr.addHandler(console_handler)

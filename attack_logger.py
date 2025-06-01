# # attack_logger.py
# import json
# import os
# from datetime import datetime

# LOG_PATH = "logs/suspicious_events.json"
# os.makedirs("logs", exist_ok=True)

# def log_suspicious_event(event_name, user_role, user_id, source_id, timestamp, context, reason):
#     log_entry = {
#         "event": event_name,
#         "role": user_role,
#         "userId": user_id,
#         "source": source_id,
#         "timestamp": timestamp.isoformat(),
#         "context": context,
#         "alert": True,
#         "reason": reason
#     }
#     with open(LOG_PATH, "a") as f:
#         f.write(json.dumps(log_entry, indent=2))  # Pretty-print JSON
#         f.write(",\n\n")  # Add spacing between entries

# attack_logger.py


import json
import os
from datetime import datetime

LOG_PATH = "logs/suspicious_events.json"
os.makedirs("logs", exist_ok=True)

def log_event(event_name, user_role, user_id, source_id, timestamp, context, alert, reason=None):
    log_entry = {
        "event": event_name,
        "role": user_role,
        "userId": user_id,
        "source": source_id,
        "timestamp": timestamp.isoformat(),
        "context": context,
        "alert": alert
    }

    if alert:
        log_entry["reason"] = reason

    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(log_entry, indent=2))
        f.write(",\n\n")

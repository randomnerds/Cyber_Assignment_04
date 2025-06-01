# attack_detector.py
from datetime import datetime, timedelta
from collections import defaultdict
from attack_logger import log_event

# Stores recent events
login_attempts = defaultdict(list)
toggle_commands = defaultdict(list)
power_readings = defaultdict(list)
session_tracker = {}
custom_event_counts = defaultdict(list)  # For additional anomaly logic


def instrument(event_name, user_role, user_id, source_id, timestamp, context):
    alert = False
    reason = ""

    # Failed login detection
    if event_name == "login_attempt" and not context.get("success", True):
        login_attempts[source_id].append(timestamp)
        login_attempts[source_id] = [
            t for t in login_attempts[source_id] if t > timestamp - timedelta(seconds=60)
        ]
        if len(login_attempts[source_id]) > 5:
            alert = True
            reason = "Too many failed login attempts"

    # Toggle device spam
    elif event_name == "toggle_device":
        toggle_commands[user_id].append(timestamp)
        toggle_commands[user_id] = [
            t for t in toggle_commands[user_id] if t > timestamp - timedelta(seconds=30)
        ]
        # if len(toggle_commands[user_id]) > 10 and user_role != "ADMIN":
        #     alert = True
        #     reason = "Device control spam detected"
        if len(toggle_commands[user_id]) > 10:
            hour = timestamp.hour
            is_business_hours = 9 <= hour < 18
            if user_role in ["ADMIN", "MANAGER"] and is_business_hours:
                alert = False  # allow it
            else:
                alert = True
                reason = "Device control spam detected"

    # Power reading anomaly
    elif event_name == "power_reading":
        value = context.get("value", 0.0)
        readings = power_readings[source_id]
        readings.append(value)
        if len(readings) > 100:
            readings.pop(0)
        avg = sum(readings) / len(readings) if readings else 1
        if value <= 0 or value > 1.5 * avg:
            alert = True
            reason = "Abnormal power usage"

    # Track session start
    elif event_name == "session_start":
        session_tracker[user_id] = timestamp

    # Access without session
    elif event_name == "access_sensitive":
        last = session_tracker.get(user_id)
        if not last or (timestamp - last > timedelta(minutes=30)):
            alert = True
            reason = "Access without active session"

    # Custom: frequent commands to thermostat
    elif event_name == "thermostat_change":
        custom_event_counts[user_id].append(timestamp)
        custom_event_counts[user_id] = [
            t for t in custom_event_counts[user_id] if t > timestamp - timedelta(seconds=45)
        ]
        if len(custom_event_counts[user_id]) > 8:
            alert = True
            reason = "Suspicious thermostat adjustment frequency"
    
    # Custom: suspecious role changes
    elif event_name == "role_change":
        active_session = session_tracker.get(user_id)
        session_valid = active_session and (timestamp - active_session <= timedelta(minutes=30))

        if session_valid:
            alert = True
            reason = "Role changed during active session"

    log_event(
        event_name=event_name,
        user_role=user_role,
        user_id=user_id,
        source_id=source_id,
        timestamp=timestamp,
        context=context,
        alert=alert,
        reason=reason if alert else None
    )

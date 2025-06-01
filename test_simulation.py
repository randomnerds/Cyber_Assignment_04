# test_simulation.py
import time
from datetime import datetime, timedelta
from attack_detector import instrument

def simulate_failed_logins():
    print("Simulating failed logins...")
    for _ in range(6):
        instrument("login_attempt", "USER", "user1", "192.168.0.10", datetime.now(), {"success": False})
        time.sleep(5)

def simulate_toggle_spam():
    print("Simulating toggle spam...")
    for _ in range(12):
        instrument("toggle_device", "USER", "user2", "device-5", datetime.now(), {})
        time.sleep(2)

def simulate_power_spike():
    print("Simulating power usage...")
    for i in range(100):
        instrument("power_reading", "SYSTEM", "sys1", "power-1", datetime.now(), {"value": 100 + i % 5})
    instrument("power_reading", "SYSTEM", "sys1", "power-1", datetime.now(), {"value": 180})

def simulate_sessionless_access():
    print("Simulating access without session...")
    instrument("access_sensitive", "USER", "user5", "192.168.0.99", datetime.now(), {})

def simulate_thermostat_spam():
    print("Simulating thermostat change spam...")
    for _ in range(9):
        instrument("thermostat_change", "USER", "user3", "thermostat-3", datetime.now(), {})
        time.sleep(4)

# def simulate_normal_usage():
#     print("Simulating normal usage (should not trigger alerts)...")

#     # Successful login
#     instrument("login_attempt", "USER", "user10", "192.168.0.20", datetime.now(), {"success": True})

#     # Toggle lights twice within 30 seconds (well below spam threshold)
#     instrument("toggle_device", "USER", "user10", "device-2", datetime.now(), {})
#     time.sleep(5)
#     instrument("toggle_device", "USER", "user10", "device-2", datetime.now(), {})

#     # Normal power readings (around average)
#     for _ in range(5):
#         instrument("power_reading", "SYSTEM", "sys-ok", "power-ok", datetime.now(), {"value": 100.0})
#         time.sleep(0.5)

#     # Start a session and access sensitive system within session period
#     now = datetime.now()
#     instrument("session_start", "USER", "user10", "192.168.0.20", now, {})
#     instrument("access_sensitive", "USER", "user10", "192.168.0.20", now + timedelta(minutes=10), {})

def simulate_normal_usage():
    print("Simulating minimal normal usage (should NOT trigger alerts)...")

    now = datetime.now()

    # Normal login (successful)
    instrument("login_attempt", "USER", "user10", "192.168.0.20", now, {"success": True})

    # Normal toggle (only once)
    instrument("toggle_device", "USER", "user10", "device-2", now + timedelta(seconds=1), {})

    # Normal power reading (in expected range)
    instrument("power_reading", "SYSTEM", "sys-ok", "power-ok", now + timedelta(seconds=2), {"value": 100.0})

    # Session-based access (within session time)
    instrument("session_start", "USER", "user10", "192.168.0.20", now + timedelta(seconds=3), {})
    instrument("access_sensitive", "USER", "user10", "192.168.0.20", now + timedelta(minutes=5), {})

    # Thermostat command (only once)
    instrument("thermostat_change", "USER", "user10", "thermostat-1", now + timedelta(seconds=4), {})



def simulate_role_aware_toggle():
    print("Simulating role-aware toggle spam tests...")

    from datetime import datetime, timedelta

    # Admin during business hours (normal)
    print("  ADMIN toggles during business hours (should NOT alert)")
    business_time = datetime.now().replace(hour=14, minute=0)  # 2 PM
    for _ in range(12):
        instrument("toggle_device", "ADMIN", "admin1", "device-X", business_time, {})
        business_time += timedelta(seconds=2)

    # Admin outside business hours (should alert)
    print("  ADMIN toggles at night (should alert)")
    night_time = datetime.now().replace(hour=2, minute=0)  # 2 AM
    for _ in range(12):
        instrument("toggle_device", "ADMIN", "admin2", "device-Y", night_time, {})
        night_time += timedelta(seconds=2)

    # Manager during business hours (normal)
    print("  MANAGER toggles during business hours (should NOT alert)")
    time_mgr = datetime.now().replace(hour=10, minute=30)  # 10:30 AM
    for _ in range(11):
        instrument("toggle_device", "MANAGER", "manager1", "device-Z", time_mgr, {})
        time_mgr += timedelta(seconds=2)

    # USER during business hours (should still alert if spammy)
    print("  USER toggles during business hours (should alert)")
    time_user = datetime.now().replace(hour=11, minute=15)
    for _ in range(12):
        instrument("toggle_device", "USER", "user9", "device-W", time_user, {})
        time_user += timedelta(seconds=2)


def simulate_role_change_during_session():
    print("Simulating role change during an active session (should trigger alert)...")

    user_id = "user8"
    source_id = "system"
    session_time = datetime.now()

    # Step 1: User starts a session
    instrument("session_start", "USER", user_id, source_id, session_time, {})

    # Step 2: Role change during session → should alert
    time.sleep(1)
    instrument("role_change", "SYSTEM", user_id, source_id, datetime.now(), {
        "old_role": "USER",
        "new_role": "ADMIN"
    })



if __name__ == "__main__":
    simulate_normal_usage()
    simulate_failed_logins()
    simulate_toggle_spam()
    simulate_power_spike()
    simulate_sessionless_access()
    simulate_thermostat_spam()
    simulate_role_aware_toggle()
    simulate_role_change_during_session()


    print("\nFinished all simulations. Check logs/suspicious_events.json for alerts.")

# test_simulation.py
import time
from datetime import datetime, timedelta
from attack_detector import instrument

# ========== NORMAL BEHAVIOR TESTS ==========

def simulate_normal_login():
    print("Simulating normal login...")
    instrument("login_attempt", "USER", "user10", "192.168.0.20", datetime.now(), {"success": True})

def simulate_normal_toggle():
    print("Simulating normal toggle...")
    instrument("toggle_device", "USER", "user10", "device-2", datetime.now(), {})

def simulate_normal_power_reading():
    print("Simulating normal power reading...")
    instrument("power_reading", "SYSTEM", "sys-ok", "power-ok", datetime.now(), {"value": 100.0})

def simulate_session_access():
    print("Simulating access with valid session...")
    now = datetime.now()
    instrument("session_start", "USER", "user10", "192.168.0.20", now, {})
    instrument("access_sensitive", "USER", "user10", "192.168.0.20", now + timedelta(minutes=10), {})

def simulate_normal_thermostat_use():
    print("Simulating single thermostat use...")
    instrument("thermostat_change", "USER", "user10", "thermostat-1", datetime.now(), {})

def simulate_role_change_without_session():
    print("Simulating role change without active session...")
    instrument("role_change", "SYSTEM", "user11", "system", datetime.now(), {
        "old_role": "USER",
        "new_role": "MANAGER"
    })

def simulate_admin_toggle_during_business_hours():
    print("Simulating ADMIN toggle during business hours...")
    t = datetime.now().replace(hour=10, minute=0)
    instrument("toggle_device", "ADMIN", "admin-ok", "device-1", t, {})


# ========== ABNORMAL BEHAVIOR TESTS ==========

def simulate_failed_logins():
    print("Simulating failed logins (should trigger alert)...")
    for _ in range(6):
        instrument("login_attempt", "USER", "user1", "192.168.0.10", datetime.now(), {"success": False})
        time.sleep(5)

def simulate_toggle_spam():
    print("Simulating toggle spam (should trigger alert)...")
    for _ in range(12):
        instrument("toggle_device", "USER", "user2", "device-5", datetime.now(), {})
        time.sleep(2)

def simulate_power_spike():
    print("Simulating power spike (should trigger alert)...")
    for i in range(100):
        instrument("power_reading", "SYSTEM", "sys1", "power-1", datetime.now(), {"value": 100 + i % 5})
    instrument("power_reading", "SYSTEM", "sys1", "power-1", datetime.now(), {"value": 180})

def simulate_sessionless_access():
    print("Simulating access without session (should trigger alert)...")
    instrument("access_sensitive", "USER", "user5", "192.168.0.99", datetime.now(), {})

def simulate_thermostat_spam():
    print("Simulating thermostat spam (should trigger alert)...")
    for _ in range(9):
        instrument("thermostat_change", "USER", "user3", "thermostat-3", datetime.now(), {})
        time.sleep(4)

def simulate_role_aware_toggle_spam():
    print("Simulating role-aware toggle spam...")

    # Admin during business hours (allowed)
    print("  ➜ ADMIN during business hours (should NOT alert)")
    t1 = datetime.now().replace(hour=14, minute=0)
    for _ in range(12):
        instrument("toggle_device", "ADMIN", "admin1", "device-X", t1, {})
        t1 += timedelta(seconds=2)

    # Admin at night (should alert)
    print("  ❗ ADMIN at night (should alert)")
    t2 = datetime.now().replace(hour=2, minute=0)
    for _ in range(12):
        instrument("toggle_device", "ADMIN", "admin2", "device-Y", t2, {})
        t2 += timedelta(seconds=2)

    # Manager during business hours (allowed)
    print("  ➜ MANAGER during business hours (should NOT alert)")
    t3 = datetime.now().replace(hour=10, minute=30)
    for _ in range(11):
        instrument("toggle_device", "MANAGER", "manager1", "device-Z", t3, {})
        t3 += timedelta(seconds=2)

    # USER during business hours (should still alert if spammy)
    print("  ❗ USER during business hours (should alert)")
    t4 = datetime.now().replace(hour=11, minute=15)
    for _ in range(12):
        instrument("toggle_device", "USER", "user9", "device-W", t4, {})
        t4 += timedelta(seconds=2)

def simulate_role_change_during_session():
    print("Simulating role change during active session (should trigger alert)...")
    user_id = "user8"
    session_time = datetime.now()
    instrument("session_start", "USER", user_id, "system", session_time, {})
    time.sleep(1)
    instrument("role_change", "SYSTEM", user_id, "system", datetime.now(), {
        "old_role": "USER",
        "new_role": "ADMIN"
    })


# ========== RUN ALL TESTS ==========

if __name__ == "__main__":
    print("========== RUNNING NORMAL USAGE TESTS ==========")
    simulate_normal_login()
    simulate_normal_toggle()
    simulate_normal_power_reading()
    simulate_session_access()
    simulate_normal_thermostat_use()
    simulate_role_change_without_session()
    simulate_admin_toggle_during_business_hours()

    print("\n========== RUNNING ABNORMAL / ATTACK TESTS ==========")
    simulate_failed_logins()
    simulate_toggle_spam()
    simulate_power_spike()
    simulate_sessionless_access()
    simulate_thermostat_spam()
    simulate_role_aware_toggle_spam()
    simulate_role_change_during_session()

    print("\nFinished all simulations. Check logs/suspicious_events.json for alerts.")

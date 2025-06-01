import unittest
import time
from datetime import datetime, timedelta
from attack_detector import instrument


class TestNormalBehavior(unittest.TestCase):

    def test_normal_login(self):
        now = datetime.now()
        instrument("login_attempt", "USER", "user10", "192.168.0.20", now, {"success": True})

    def test_normal_toggle(self):
        now = datetime.now()
        instrument("toggle_device", "USER", "user10", "device-2", now, {})

    def test_normal_power_reading(self):
        now = datetime.now()
        instrument("power_reading", "SYSTEM", "sys-ok", "power-ok", now, {"value": 100.0})

    def test_session_access(self):
        now = datetime.now()
        instrument("session_start", "USER", "user10", "192.168.0.20", now, {})
        instrument("access_sensitive", "USER", "user10", "192.168.0.20", now + timedelta(minutes=5), {})

    def test_normal_thermostat_use(self):
        now = datetime.now()
        instrument("thermostat_change", "USER", "user10", "thermostat-1", now, {})

    def test_role_change_without_session(self):
        now = datetime.now()
        instrument("role_change", "SYSTEM", "user11", "system", now, {
            "old_role": "USER",
            "new_role": "MANAGER"
        })

    def test_admin_toggle_business_hours(self):
        t = datetime.now().replace(hour=10, minute=0)
        instrument("toggle_device", "ADMIN", "admin-ok", "device-1", t, {})


class TestAbnormalBehavior(unittest.TestCase):

    def test_failed_logins(self):
        for _ in range(6):
            instrument("login_attempt", "USER", "user1", "192.168.0.10", datetime.now(), {"success": False})
            time.sleep(1)

    def test_toggle_spam(self):
        for _ in range(12):
            instrument("toggle_device", "USER", "user2", "device-5", datetime.now(), {})
            time.sleep(0.5)

    def test_power_spike(self):
        for i in range(5):
            instrument("power_reading", "SYSTEM", "sys1", "power-1", datetime.now(), {"value": 100 + i % 5})
        instrument("power_reading", "SYSTEM", "sys1", "power-1", datetime.now(), {"value": 180})

    def test_sessionless_access(self):
        instrument("access_sensitive", "USER", "user5", "192.168.0.99", datetime.now(), {})

    def test_thermostat_spam(self):
        for _ in range(9):
            instrument("thermostat_change", "USER", "user3", "thermostat-3", datetime.now(), {})
            time.sleep(1)

    def test_role_aware_toggle_spam(self):
        print("\n  ➜ ADMIN during business hours (should NOT alert)")
        t1 = datetime.now().replace(hour=14, minute=0)
        for _ in range(12):
            instrument("toggle_device", "ADMIN", "admin1", "device-X", t1, {})
            t1 += timedelta(seconds=2)

        print("  ❗ ADMIN at night (should alert)")
        t2 = datetime.now().replace(hour=2, minute=0)
        for _ in range(12):
            instrument("toggle_device", "ADMIN", "admin2", "device-Y", t2, {})
            t2 += timedelta(seconds=2)

        print("  ➜ MANAGER during business hours (should NOT alert)")
        t3 = datetime.now().replace(hour=10, minute=30)
        for _ in range(11):
            instrument("toggle_device", "MANAGER", "manager1", "device-Z", t3, {})
            t3 += timedelta(seconds=2)

        print("  ❗ USER spam (should alert)")
        t4 = datetime.now().replace(hour=11, minute=15)
        for _ in range(12):
            instrument("toggle_device", "USER", "user9", "device-W", t4, {})
            t4 += timedelta(seconds=2)

    def test_role_change_during_session(self):
        user_id = "user8"
        source_id = "system"
        session_time = datetime.now()
        instrument("session_start", "USER", user_id, source_id, session_time, {})
        time.sleep(1)
        instrument("role_change", "SYSTEM", user_id, source_id, datetime.now(), {
            "old_role": "USER",
            "new_role": "ADMIN"
        })


if __name__ == "__main__":
    print("\n========= RUNNING UNIT TESTS =========\n")
    unittest.main()

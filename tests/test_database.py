"""
test_database.py — Tests for database operations
"""
import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import database

def setup_test_db():
    import tempfile
    original = database.DB_PATH
    fd, database.DB_PATH = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    database.init_db()
    return original

def teardown_test_db(original):
    database.DB_PATH = original

def test_register_and_verify_user():
    original = setup_test_db()
    try:
        result = database.register_user("testuser", "test@gmail.com", "Test@1234")
        assert result["ok"] == True
        
        user = database.verify_user("testuser", "Test@1234")
        assert user is not None
        assert user["username"] == "testuser"
        
        invalid = database.verify_user("testuser", "WrongPass")
        assert invalid is None
        print("✓ User registration and verification tests passed")
    finally:
        teardown_test_db(original)

def test_get_user_by_email():
    original = setup_test_db()
    try:
        database.register_user("testuser2", "test2@gmail.com", "Test@1234")
        user = database.get_user_by_email("test2@gmail.com")
        assert user is not None
        assert user["username"] == "testuser2"
        print("✓ Get user by email tests passed")
    finally:
        teardown_test_db(original)

def test_whitelist_add_remove():
    original = setup_test_db()
    try:
        result = database.whitelist_add("aa:bb:cc:dd:ee:ff", "Test AP", "TestSSID")
        assert result["ok"] == True
        
        result = database.whitelist_add("aa:bb:cc:dd:ee:ff", "Test AP", "TestSSID")
        assert result["ok"] == False
        
        result = database.whitelist_remove("aa:bb:cc:dd:ee:ff")
        assert result["ok"] == True
        
        result = database.whitelist_remove("aa:bb:cc:dd:ee:ff")
        assert result["ok"] == False
        print("✓ Whitelist add/remove tests passed")
    finally:
        teardown_test_db(original)

def test_whitelist_validation():
    original = setup_test_db()
    try:
        result = database.whitelist_add("invalid-bssid", "Test", "Test")
        assert result["ok"] == False
        assert "Invalid BSSID" in result["error"]
        
        result = database.whitelist_add("aa:bb:cc:dd:ee:ff", "Valid", "Test")
        assert result["ok"] == True
        print("✓ BSSID validation tests passed")
    finally:
        teardown_test_db(original)

def test_scan_operations():
    original = setup_test_db()
    try:
        result = {
            "stats": {"rogue_count": 1, "suspicious_count": 2, "total_frames": 100, "total_findings": 5},
            "timestamp": "2024-01-01T00:00:00",
            "source_files": ["test.csv"]
        }
        database.scan_save("test_scan_1", result)
        
        scans = database.scan_list()
        assert len(scans) == 1
        assert scans[0]["scan_id"] == "test_scan_1"
        
        scan = database.scan_get("test_scan_1")
        assert scan is not None
        assert scan["stats"]["rogue_count"] == 1
        
        database.scan_delete("test_scan_1")
        scans = database.scan_list()
        assert len(scans) == 0
        print("✓ Scan operations tests passed")
    finally:
        teardown_test_db(original)

def test_password_change():
    original = setup_test_db()
    try:
        database.register_user("pwtest", "pwtest@gmail.com", "OldPass@123")
        
        assert database.verify_user("pwtest", "OldPass@123") is not None
        assert database.verify_user("pwtest", "NewPass@123") is None
        
        database.user_change_password("pwtest", "NewPass@123")
        
        assert database.verify_user("pwtest", "OldPass@123") is None
        assert database.verify_user("pwtest", "NewPass@123") is not None
        print("✓ Password change tests passed")
    finally:
        teardown_test_db(original)

def run_all_tests():
    print("\nRunning database tests...\n")
    test_register_and_verify_user()
    test_get_user_by_email()
    test_whitelist_add_remove()
    test_whitelist_validation()
    test_scan_operations()
    test_password_change()
    print("\n✓ All database tests passed!\n")

if __name__ == '__main__':
    run_all_tests()

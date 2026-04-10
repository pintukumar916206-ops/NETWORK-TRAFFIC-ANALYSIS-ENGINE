import requests
import time
import sys

BASE_URL = "http://127.0.0.1:5000"

def test_auth_rate_limit():
    print(f"Testing rate limit on {BASE_URL}/login...")
    
    # Try logging in 5 times (should succeed or get 401, but not 429)
    for i in range(1, 6):
        try:
            resp = requests.post(f"{BASE_URL}/login", json={"username": "admin", "password": "wrong"})
            print(f"Attempt {i}: Status {resp.status_code}")
            if resp.status_code == 429:
                print("FAILED: Got 429 too early!")
                return False
        except requests.ConnectionError:
            print("FAILED: Could not connect to the server. Is it running?")
            return False

    # 6th attempt should be rate limited
    resp = requests.post(f"{BASE_URL}/login", json={"username": "admin", "password": "wrong"})
    print(f"Attempt 6: Status {resp.status_code}")
    
    if resp.status_code == 429:
        print("SUCCESS: Rate limiting is working for auth routes (5 per 15 min)")
        return True
    else:
        print(f"FAILED: Expected 429, but got {resp.status_code}")
        return False

def test_global_rate_limit():
    print(f"\nTesting global rate limit on {BASE_URL}/...")
    # Default is 100 per hour, we'll just check if it's reachable
    resp = requests.get(f"{BASE_URL}/")
    print(f"Root: Status {resp.status_code}")
    return resp.status_code == 200

if __name__ == "__main__":
    if not test_global_rate_limit():
        sys.exit(1)
    if not test_auth_rate_limit():
        sys.exit(1)
    print("\nAll tests passed!")

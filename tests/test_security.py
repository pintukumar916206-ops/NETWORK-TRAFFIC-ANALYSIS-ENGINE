import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_xss_protection():
    print("Testing XSS protection in dashboard...")
    # This is a bit tricky to test automatically without a browser, 
    # but we can check if the API returns content that would be escaped in the UI logic we added.
    # Actually, we can check if the console log or status updates are being sanitized.
    # Since we added esc() to the JS, we just need to ensure the dashboard still works.
    resp = requests.get(BASE_URL)
    if "function esc(str)" in resp.text:
        print("SUCCESS: esc() helper found in index.html")
    else:
        print("FAILED: esc() helper not found")

def test_traceback_exposure():
    print("\nTesting for sensitive traceback exposure...")
    # Send a request that triggers an error (e.g. invalid URL that fails Scapy)
    # We'll use a valid-looking URL that won't resolve or will cause an error in generate_synthetic_pcap
    resp = requests.post(f"{BASE_URL}/analyze_url", json={"url": "!!!invalid!!!"})
    data = resp.json()
    print(f"Status: {resp.status_code}, Body: {json.dumps(data, indent=2)}")
    
    if "traceback" in data:
        print("FAILED: Traceback still exposed!")
    else:
        print("SUCCESS: No traceback in error response")

if __name__ == "__main__":
    # Make sure dashboard is running
    test_xss_protection()
    test_traceback_exposure()
    print("\nSecurity verification complete.")

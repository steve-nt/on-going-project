import requests
import json

BASE_URL = "http://localhost:5050"

def test_registration():
    # Test different hash types
    users = [
        {"username": "user1", "password": "test123", "hash_type": "sha256"},
        {"username": "user2", "password": "test123", "hash_type": "bcrypt"},
        {"username": "user3", "password": "test123", "hash_type": "argon2"},
    ]
    
    for user in users:
        response = requests.post(f"{BASE_URL}/register", json=user)
        print(f"Registered {user['username']} with {user['hash_type']}: {response.json()}")

def test_login():
    response = requests.post(f"{BASE_URL}/login", 
                           json={"username": "user1", "password": "test123"})
    print(f"Login response: {response.json()}")

if __name__ == "__main__":
    test_registration()
    test_login()

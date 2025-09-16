# test_backend.py
import requests

BASE_URL = "http://localhost:3000"
token = None

def test_auth():
    global token
    print("=== Testing Registration ===")
    try:
        res = requests.post(f"{BASE_URL}/api/auth/register", json={
            "studentId": "20250004",
            "username": "testuser",
            "password": "password123"
        })
        print(res.json())
    except Exception as e:
        print("Registration error:", e)

    print("\n=== Testing Login ===")
    try:
        res = requests.post(f"{BASE_URL}/api/auth/login", json={
            "studentId": "20250004",
            "password": "password123"
        })
        data = res.json()
        print(data)
        token = data.get("token")
        print("Token:", token)
    except Exception as e:
        print("Login error:", e)

    print("\n=== Testing Get Profile (/api/auth/me) ===")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        res = requests.get(f"{BASE_URL}/api/auth/me", headers=headers)
        print(res.json())
    except Exception as e:
        print("Profile error:", e)

def test_merchants():
    headers = {"Authorization": f"Bearer {token}"}

    print("\n=== Testing Get All Merchants ===")
    try:
        res = requests.get(f"{BASE_URL}/api/merchants/")
        print(res.json())
    except Exception as e:
        print("Get merchants error:", e)

    print("\n=== Testing Create Merchant ===")
    try:
        res = requests.post(f"{BASE_URL}/api/merchants/", json={
            "id": "merchant1",
            "name": "Test Merchant",
            "address": "123 Blockchain Ave",
            "category": "Food"
        }, headers=headers)
        print(res.json())
    except Exception as e:
        print("Create merchant error:", e)

    print("\n=== Testing Get Merchant By ID ===")
    try:
        res = requests.get(f"{BASE_URL}/api/merchants/merchant1")
        print(res.json())
    except Exception as e:
        print("Get merchant error:", e)

def test_reviews():
    headers = {"Authorization": f"Bearer {token}"}

    print("\n=== Testing Submit Review ===")
    try:
        res = requests.post(f"{BASE_URL}/api/reviews/", json={
            "merchantId": "merchant1",
            "rating": 5,
            "comment": "Great service!",
            "imageHash": "QmTestImageHash"
        }, headers=headers)
        print(res.json())
    except Exception as e:
        print("Submit review error:", e)

    print("\n=== Testing Get My Reviews ===")
    try:
        res = requests.get(f"{BASE_URL}/api/reviews/my", headers=headers)
        print(res.json())
    except Exception as e:
        print("Get my reviews error:", e)

if __name__ == "__main__":
    test_auth()
    test_merchants()
    test_reviews()

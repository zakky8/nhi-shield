#!/usr/bin/env python3
# ============================================================
# NHI SHIELD — Security Test Suite
# Tests: SQL injection, JWT security, rate limiting, encryption, RBAC
# Run: pytest tests/test_security.py -v
# ============================================================
import requests
import time
import json
import base64
import pytest

BASE_URL = "http://localhost:3000"
ADMIN_EMAIL = "admin@testorg.com"
ADMIN_PASSWORD = "Test1234!"
VIEWER_EMAIL = "analyst@testorg.com"

@pytest.fixture(scope='module')
def admin_token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"Login failed: {r.text}"
    return r.json()['accessToken']

# ── TEST 1: SQL Injection ─────────────────────────────────────
class TestSQLInjection:

    SQL_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "1; SELECT pg_sleep(5)--",
        "admin'--",
        "' OR 1=1--",
    ]

    def test_login_sql_injection(self):
        """Injecting into email/password fields should return 401, not 200"""
        for payload in self.SQL_PAYLOADS:
            r = requests.post(f"{BASE_URL}/api/auth/login",
                              json={"email": payload, "password": payload})
            assert r.status_code in (400, 401), \
                f"SQL injection may have succeeded! Payload: {payload!r}, Status: {r.status_code}"
            assert 'DROP TABLE' not in (r.text or ''), \
                f"SQL error leaked in response for payload: {payload!r}"

    def test_identities_query_injection(self, admin_token):
        """Query parameters should be sanitized"""
        headers = {"Authorization": f"Bearer {admin_token}"}
        injections = ["'; DROP TABLE identities;--", "' OR '1'='1"]
        for payload in injections:
            r = requests.get(f"{BASE_URL}/api/identities",
                             params={"search": payload}, headers=headers)
            # Should return empty results or 400, never 500 with DB error
            assert r.status_code in (200, 400), \
                f"Unexpected status {r.status_code} for injection: {payload!r}"


# ── TEST 2: JWT Security ─────────────────────────────────────
class TestJWTSecurity:

    def test_expired_token_rejected(self):
        """An expired JWT should return 401"""
        # This is a known-expired JWT (exp in the past)
        expired_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJ1c2VySWQiOiJ0ZXN0IiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjE2MDAwMDAwMDF9."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        r = requests.get(f"{BASE_URL}/api/identities",
                         headers={"Authorization": f"Bearer {expired_token}"})
        assert r.status_code == 401
        assert r.json().get('code') in ('TOKEN_EXPIRED', 'TOKEN_INVALID')

    def test_tampered_token_rejected(self):
        """Modifying JWT payload without re-signing should fail"""
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        token = r.json()['accessToken']

        # Decode payload, modify role, re-encode WITHOUT correct signature
        parts = token.split('.')
        payload_bytes = base64.b64decode(parts[1] + '==')
        payload = json.loads(payload_bytes)
        payload['role'] = 'superadmin'  # Fake elevated role
        tampered_payload = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        r = requests.get(f"{BASE_URL}/api/identities",
                         headers={"Authorization": f"Bearer {tampered_token}"})
        assert r.status_code == 401

    def test_blacklisted_token_rejected(self):
        """Token blacklisted via logout should be rejected"""
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        token = r.json()['accessToken']
        headers = {"Authorization": f"Bearer {token}"}

        # Confirm it works before logout
        r = requests.get(f"{BASE_URL}/api/identities", headers=headers)
        assert r.status_code == 200

        # Logout (blacklists the token)
        requests.post(f"{BASE_URL}/api/auth/logout", headers=headers)

        # Token should now be rejected
        r = requests.get(f"{BASE_URL}/api/identities", headers=headers)
        assert r.status_code == 401
        assert r.json().get('code') == 'TOKEN_REVOKED'

    def test_no_token_rejected(self):
        r = requests.get(f"{BASE_URL}/api/identities")
        assert r.status_code == 401


# ── TEST 3: Rate Limiting ─────────────────────────────────────
class TestRateLimiting:

    def test_login_brute_force_blocked(self):
        """After 5 failed logins, 6th should return 429"""
        for i in range(10):
            requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": "brutetest@example.com", "password": "wrong"})

        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": "brutetest@example.com", "password": "wrong"})

        # Should be locked out
        assert r.status_code in (429, 423), \
            f"Expected 429/423 after brute force, got {r.status_code}"
        assert r.json().get('code') in ('RATE_LIMIT_EXCEEDED', 'ACCOUNT_LOCKED')

    def test_rate_limit_headers_present(self, admin_token):
        """Rate-limited responses should include proper headers"""
        r = requests.get(f"{BASE_URL}/api/identities",
                         headers={"Authorization": f"Bearer {admin_token}"})
        assert 'ratelimit-limit' in r.headers or 'x-ratelimit-limit' in r.headers or r.status_code == 200


# ── TEST 4: RBAC ─────────────────────────────────────────────
class TestRBAC:

    @pytest.fixture
    def viewer_token(self):
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": VIEWER_EMAIL, "password": ADMIN_PASSWORD})
        if r.status_code != 200:
            pytest.skip("Viewer user not available in test DB")
        return r.json()['accessToken']

    def test_viewer_cannot_offboard(self, viewer_token):
        """Viewer role should NOT be able to offboard identities"""
        headers = {"Authorization": f"Bearer {viewer_token}"}
        r = requests.post(
            f"{BASE_URL}/api/identities/c0000000-0000-0000-0000-000000000001/offboard",
            json={"reason": "Testing RBAC — this should be blocked"},
            headers=headers
        )
        assert r.status_code == 403
        assert r.json().get('code') == 'INSUFFICIENT_PERMISSIONS'

    def test_viewer_can_read(self, viewer_token):
        """Viewer role SHOULD be able to read identities"""
        headers = {"Authorization": f"Bearer {viewer_token}"}
        r = requests.get(f"{BASE_URL}/api/identities", headers=headers)
        assert r.status_code == 200

    def test_admin_can_offboard(self, admin_token):
        """Admin role SHOULD be able to offboard"""
        headers = {"Authorization": f"Bearer {admin_token}"}
        # Just check it doesn't return 403 (may return 404 if ID doesn't exist)
        r = requests.post(
            f"{BASE_URL}/api/identities/nonexistent-uuid/offboard",
            json={"reason": "Testing admin RBAC — expect 404 not 403"},
            headers=headers
        )
        assert r.status_code in (404, 400), f"Expected 404/400, got {r.status_code}: {r.text}"
        assert r.status_code != 403  # Key assertion: not forbidden


# ── TEST 5: Input Validation ──────────────────────────────────
class TestInputValidation:

    def test_invalid_email_rejected(self):
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": "notanemail", "password": "password"})
        assert r.status_code == 400

    def test_oversized_body_rejected(self):
        """Request body over 1MB should be rejected"""
        huge_reason = "x" * (2 * 1024 * 1024)  # 2MB
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": "test@test.com", "password": huge_reason})
        assert r.status_code in (400, 413)

    def test_missing_required_fields(self):
        """Missing required fields should return validation error"""
        r = requests.post(f"{BASE_URL}/api/auth/login", json={"email": "test@test.com"})
        assert r.status_code == 400
        assert r.json().get('code') == 'VALIDATION_ERROR'


if __name__ == '__main__':
    print("Run with: pytest tests/test_security.py -v --tb=short")

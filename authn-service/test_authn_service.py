"""Tests for authn-service Flask application."""
import os
import sys
import pytest
import jwt as pyjwt
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Tests for get_access_token()
# ---------------------------------------------------------------------------

class TestGetAccessToken:
    def _call(self, mock_response):
        with patch("authn_service.requests.post") as mock_post:
            mock_post.return_value = mock_response
            import authn_service
            return authn_service.get_access_token("test_code")

    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "ghs_token123",
            "scope": "user",
            "token_type": "bearer",
        }
        result, error = self._call(mock_resp)
        assert error is None
        assert result["access_token"] == "ghs_token123"
        assert result["scope"] == "user"
        assert result["token_type"] == "bearer"

    def test_github_error_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {
            "error": "bad_verification_code",
            "error_description": "The code passed is incorrect or expired.",
        }
        result, error = self._call(mock_resp)
        assert result is None
        assert error == "The code passed is incorrect or expired."


# ---------------------------------------------------------------------------
# Tests for get_user_profile()
# ---------------------------------------------------------------------------

class TestGetUserProfile:
    def _call(self, mock_response):
        with patch("authn_service.requests.get") as mock_get:
            mock_get.return_value = mock_response
            import authn_service
            return authn_service.get_user_profile("ghs_token123")

    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "login": "octocat",
            "name": "The Octocat",
            "email": "octocat@github.com",
            "id": 1,
        }
        profile, error = self._call(mock_resp)
        assert error is None
        assert profile["login"] == "octocat"
        assert profile["name"] == "The Octocat"

    def test_error_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.json.return_value = {
            "error": "invalid_token",
            "error_description": "Token is invalid",
        }
        profile, error = self._call(mock_resp)
        assert profile is None
        assert error == "Token is invalid"


# ---------------------------------------------------------------------------
# Tests for the /authenticate/<code> route
# ---------------------------------------------------------------------------

_JWT_SECRET = "secretsecret1234secretsecret1234"
_original_jwt_encode = pyjwt.encode


def _compat_jwt_encode(claimset, secret, algorithm):
    """Return jwt.encode result as bytes to match the app's PyJWT 1.x expectation."""
    token = _original_jwt_encode(claimset, secret, algorithm=algorithm)
    # PyJWT 2.x returns str; encode to bytes so .decode() in the app code succeeds
    return token.encode("utf-8") if isinstance(token, str) else token


@pytest.fixture
def client():
    import authn_service
    authn_service.app.config["TESTING"] = True
    with authn_service.app.test_client() as c:
        yield c


class TestAuthenticateRoute:
    def test_success_returns_token(self, client):
        import authn_service
        access_info = {"access_token": "ghs_token123", "scope": "user", "token_type": "bearer"}
        profile = {"login": "octocat", "name": "The Octocat", "email": "octocat@github.com", "id": 1}

        with patch.object(authn_service, "get_access_token", return_value=(access_info, None)), \
             patch.object(authn_service, "get_user_profile", return_value=(profile, None)), \
             patch.object(authn_service.jwt, "encode", side_effect=_compat_jwt_encode):
            resp = client.get("/authenticate/validcode")

        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert isinstance(data["token"], str)
        assert len(data["token"]) > 0

    def test_access_token_error_returns_error(self, client):
        import authn_service
        with patch.object(authn_service, "get_access_token", return_value=(None, "bad code")):
            resp = client.get("/authenticate/badcode")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["error"] == "bad code"

    def test_profile_error_returns_error(self, client):
        import authn_service
        access_info = {"access_token": "ghs_token", "scope": "user", "token_type": "bearer"}
        with patch.object(authn_service, "get_access_token", return_value=(access_info, None)), \
             patch.object(authn_service, "get_user_profile", return_value=(None, "profile error")):
            resp = client.get("/authenticate/code")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["error"] == "profile error"

    def test_token_contains_expected_claims(self, client):
        """Verify the returned JWT encodes the correct profile claims."""
        import authn_service
        access_info = {"access_token": "ghs_token", "scope": "user", "token_type": "bearer"}
        profile = {"login": "testuser", "name": "Test User", "email": "test@example.com", "id": 99}

        with patch.object(authn_service, "get_access_token", return_value=(access_info, None)), \
             patch.object(authn_service, "get_user_profile", return_value=(profile, None)), \
             patch.object(authn_service.jwt, "encode", side_effect=_compat_jwt_encode):
            resp = client.get("/authenticate/mycode")

        assert resp.status_code == 200
        data = resp.get_json()
        token = data["token"]

        decoded = pyjwt.decode(token, options={"verify_signature": False})
        assert decoded["iss"] == "OctoGallery"
        assert decoded["profile"]["login"] == "testuser"
        assert decoded["profile"]["name"] == "Test User"
        assert decoded["profile"]["email"] == "test@example.com"
        # 'id' should not be included – only login/name/email are forwarded
        assert "id" not in decoded["profile"]


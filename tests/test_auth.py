# test_auth.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from main import app
from conftest import MockResponse
from bs4 import BeautifulSoup

client = TestClient(app)
print("Loaded app from:", [route.path for route in app.routes])
def test_login_redirect():
    response = client.get("/login", follow_redirects=False)
    print(f"Response body: {response.text}")
    assert response.status_code == 307
    assert "accounts.google.com" in response.headers["location"]

@patch("main.requests.post")
@patch("main.requests.get")
def test_auth_callback(mock_get, mock_post):
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "access_token": "mock_access_token"
    }
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "email": "test@example.com",
        "name": "Test User",
        "id": "testid123",
        "picture": "http://example.com/pic.jpg"
    }

    response = client.get("/auth/callback?code=mock_code")
    assert response.status_code in (200, 307)

@patch("main.create_access_token")
@patch("main.requests.get")
@patch("main.requests.post")
def test_auth_callback_new_user_success(mock_post, mock_get, mock_create_token):
    # Step 1: Mock token exchange (first POST call)
    mock_token_response = Mock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {"access_token": "fake_access"}

    # Step 2: Mock DB service user creation (second POST call)
    mock_post.side_effect = [mock_token_response, Mock(status_code=200)]

    # Step 3: Mock Google userinfo GET
    mock_get.return_value.json.return_value = {
        "id": "test_user_id_1",
        "email": "test1@example.com",
        "name": "Test User 1"
    }

    # Step 4: Mock JWT token creation
    mock_create_token.return_value = "jwt_token"

    # Call the endpoint
    response = client.get("/auth/callback?code=fake_code", follow_redirects=True)

    # Validate response
    assert response.status_code == 200
    assert "Login Successful" in response.text
    assert "Welcome, Test User 1" in response.text
    assert "test1@example.com" in response.text

@patch("main.create_access_token")
@patch("main.requests.get")
@patch("main.requests.post")
def test_auth_callback_existing_user_success(mock_post, mock_get, mock_create_token):
    # Step 1: Mock token exchange (POST to Google token endpoint)
    mock_token_response = Mock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {"access_token": "fake_access"}

    # Step 2: Mock DB service user creation (POST to DB microservice)
    mock_db_response = Mock()
    mock_db_response.status_code = 400  # User already exists

    # Use side_effect to simulate both POST requests in order
    mock_post.side_effect = [mock_token_response, mock_db_response]

    # Step 3: Mock GET to Google userinfo
    mock_get.return_value.json.return_value = {
        "id": "test_user_id_2",
        "email": "test2@example.com",
        "name": "Test User 2"
    }

    # Step 4: Mock JWT token creation
    mock_create_token.return_value = "jwt_token"

    # Step 5: Make the request
    response = client.get("/auth/callback?code=fake_code", follow_redirects=True)

    # Step 6: Validate
    assert response.status_code == 200
    assert "Login Successful" in response.text
    soup = BeautifulSoup(response.text, "html.parser")
    print("Response text:", soup.prettify())
    assert "Welcome back, Test User 2" in response.text
    assert "test2@example.com" in response.text

@patch("main.create_access_token")
@patch("main.requests.get")
@patch("main.requests.post")
def test_auth_callback_existing_user_unknown_error(mock_post, mock_get, mock_create_token):
    # Step 1: Mock token exchange (POST to Google token endpoint)
    mock_token_response = Mock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {"access_token": "fake_access"}

    # Step 2: Mock DB service user creation (POST to DB microservice)
    mock_db_response = Mock()
    mock_db_response.status_code = 500  # User already exists

    # Use side_effect to simulate both POST requests in order
    mock_post.side_effect = [mock_token_response, mock_db_response]

    # Step 3: Mock GET to Google userinfo
    mock_get.return_value.json.return_value = {
        "id": "test_user_id_2",
        "email": "test2@example.com",
        "name": "Test User 2"
    }

    # Step 4: Mock JWT token creation
    mock_create_token.return_value = "jwt_token"

    # Step 5: Make the request
    response = client.get("/auth/callback?code=fake_code", follow_redirects=True)

    # Step 6: Validate
    assert response.status_code == 200
    assert "Login Successful" in response.text
    soup = BeautifulSoup(response.text, "html.parser")
    print("Response text:", soup.prettify())
    assert "Unknown error. Error code: 500" in response.text
    assert "test2@example.com" in response.text

@patch("main.create_access_token")
@patch("main.requests.get")
@patch("main.requests.post")
def test_auth_callback_db_failure_returns_500(mock_post, mock_get, mock_create_token):
    # First mock: Google token exchange
    mock_token_response = Mock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {"access_token": "fake_access"}

    # Simulate DB exception on second POST
    def raise_db_error(*args, **kwargs):
        raise Exception("Simulated DB failure")

    mock_post.side_effect = [mock_token_response, raise_db_error]

    # Mock user info returned from Google
    mock_get.return_value.json.return_value = {
        "id": "test_user_id_5",
        "email": "test5@example.com",
        "name": "Test User 5"
    }

    mock_create_token.return_value = "jwt_token"

    response = client.get("/auth/callback?code=fake_code", follow_redirects=True)

    assert response.status_code == 500
    assert response.json()["detail"] == "Internal Server Error"
import pytest
from datetime import timedelta, datetime
from jose import jwt, JWTError
from jwt.exceptions import InvalidSignatureError
from jwt.exceptions import ExpiredSignatureError
from jwt_utils import create_access_token, decode_access_token, SECRET_KEY, ALGORITHM

def test_create_access_token_contains_expected_claims():
    payload = {"sub": "user_id_123"}
    token = create_access_token(payload)
    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    
    assert decoded["sub"] == "user_id_123"
    assert "exp" in decoded

def test_create_access_token_expiry_respected():
    payload = {"sub": "user_id_456"}
    token = create_access_token(payload, expires_delta=timedelta(minutes=1))
    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    exp = datetime.utcfromtimestamp(decoded["exp"])
    
    assert exp <= datetime.utcnow() + timedelta(minutes=1, seconds=5)

def test_decode_access_token_valid():
    data = {"sub": "user_id_test"}
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    decoded = decode_access_token(token)
    
    assert decoded["sub"] == "user_id_test"

def test_decode_access_token_invalid_signature():
    data = {"sub": "tampered_user"}
    wrong_secret = "wrongsecret"
    tampered_token = jwt.encode(data, wrong_secret, algorithm=ALGORITHM)

    with pytest.raises(InvalidSignatureError, match="Signature verification failed"):
        decode_access_token(tampered_token)

def test_decode_expired_access_token():
    payload = {
        "sub": "expired_user",
        "exp": datetime.utcnow() - timedelta(seconds=1)
    }
    expired_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    with pytest.raises(ExpiredSignatureError, match="Signature has expired"):
        decode_access_token(expired_token)
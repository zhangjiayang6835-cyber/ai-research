import time
import pytest
from src.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_timing_attack(client):
    """
    Test that invalid usernames and valid usernames with wrong passwords
    take roughly the same amount of time to reject.
    """
    # Time for invalid username
    start = time.time()
    for _ in range(100):
        client.post('/login', data={'username': 'nonexistent', 'password': 'wrongpassword'})
    invalid_user_time = time.time() - start

    # Time for valid username but wrong password
    start = time.time()
    for _ in range(100):
        client.post('/login', data={'username': 'admin', 'password': 'wrongpassword'})
    valid_user_time = time.time() - start

    # They should be very close, within 0.1 seconds for 100 requests usually,
    # but we just assert they are somewhat similar.
    # Actually, hmac.compare_digest is fast.
    # The main thing is they should not have a 10x difference.
    ratio = valid_user_time / invalid_user_time if invalid_user_time > 0 else 1
    assert 0.5 < ratio < 2.0

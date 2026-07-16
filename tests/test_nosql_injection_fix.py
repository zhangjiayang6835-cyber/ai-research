import pytest
from fixes.nosql_injection_fix import safe_login_query

import hashlib

def test_safe_login_query_valid():
    query = safe_login_query("admin", "password123")
    expected_hash = hashlib.sha256("password123".encode()).hexdigest()
    assert query == {"username": "admin", "password": expected_hash}

def test_safe_login_query_dict_injection():
    # If the user passes a dict, it should be rejected because it's not a string
    query = safe_login_query("admin", {"$ne": ""})  # type: ignore
    assert query == {}

def test_safe_login_query_list_injection():
    query = safe_login_query({"$gt": ""}, "password")  # type: ignore
    assert query == {}

def test_safe_login_query_suspicious_chars():
    query = safe_login_query("admin", "p$ssword")
    assert query == {}
    
def test_safe_login_query_suspicious_chars_user():
    query = safe_login_query("adm$in", "password")
    assert query == {}

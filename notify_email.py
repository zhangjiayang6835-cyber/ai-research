def verify_jwt(token):
    allowed_algorithms = ['RS256']
    alg = jwt.get_unverified_header(token).get('alg')
    
    if alg not in allowed_algorithms:
        raise ValueError("Unsupported algorithm")
    
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": True})
    except jwt.exceptions.InvalidTokenError as e:
        raise ValueError(str(e))
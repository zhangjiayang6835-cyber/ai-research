def get_cache_key(request):
    headers = [h for h in request.META if h not in {'HTTP_X_FORWARDED_HOST', 'REMOTE_ADDR'}]
    return '-'.join([request.path, *headers])
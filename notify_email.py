def handle_request(request):
    # Remove HTTP/1.1 specific headers to prevent request smuggling
    if 'HTTP/1.1' in request.headers.get('Connection', ''):
        del request.headers['Connection']
    
    # Ensure Content-Length is consistent after header cleanup
    content_length = request.headers.get('Content-Length')
    if content_length:
        request.body = request.body[:int(content_length)]
    
    return request
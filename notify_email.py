def parse_url(url):
    allowed_schemes = {'http', 'https'}
    if url.startswith('gopher://') or url.startswith(('dict://', 'file://')):
        raise ValueError("Unsupported protocol")
    
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in allowed_schemes:
        raise ValueError("Invalid scheme")

    ip = parsed.netloc.split(':')[0]
    internal_ips = {'127.0.0.1', '::1'}
    if ip in internal_ips:
        raise ValueError("Internal IP detected")

    return urllib.parse.urlunparse(parsed._replace(scheme=parsed.scheme.lower()))
import requests

def fetch_data(url):
    response = requests.get(url, allow_redirects=False)
    if response.status_code == 200 and not is_private_ip(response.url):
        return response.content
    else:
        raise ValueError("Invalid or private IP response")

def is_private_ip(url):
    private_ips = [
        "169.254.169.254",  # AWS metadata
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ]
    parsed_url = requests.utils.urlparse(url)
    return any(parsed_url.netloc in ip for ip in private_ips)

# Example usage
try:
    data = fetch_data("http://example.com")
    print(data)
except ValueError as e:
    print(e)
import re
import ipaddress
import socket
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional
import requests

# Private and reserved IP networks for SSRF protection
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local / Cloud Metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 ranges
    ipaddress.ip_network("::1/128"),              # Localhost
    ipaddress.ip_network("fc00::/7"),             # Unique local
    ipaddress.ip_network("fe80::/10"),            # Link-local
    ipaddress.ip_network("::ffff:0:0/96"),        # IPv4-mapped IPv6
]

BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "127.0.0.1", "::1",
    "metadata.google.internal", "instance-data",
    "169.254.169.254"
}

# Simple in-memory cache for resolved redirect chains
_RESOLUTION_CACHE: Dict[str, Dict[str, Any]] = {}
MAX_CACHE_SIZE = 1000

def is_safe_ip(ip_str: str) -> bool:
    """Check if an IP address is publicly routable and not in private/internal ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False
        for blocked_net in BLOCKED_IP_NETWORKS:
            if ip_obj in blocked_net:
                return False
        return True
    except ValueError:
        return False

def validate_url_for_ssrf(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a URL against SSRF threats by inspecting scheme, hostname, and resolved IP.
    Returns (is_safe, error_message).
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, f"Malformed URL format: {str(e)}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Unsupported URL scheme: '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL missing valid hostname."

    hostname_clean = hostname.strip().lower()

    if hostname_clean in BLOCKED_HOSTNAMES or hostname_clean.endswith(".local") or hostname_clean.endswith(".internal"):
        return False, f"Blocked internal or loopback hostname: '{hostname_clean}'."

    # Check direct IP literals in URL hostname
    try:
        ip_obj = ipaddress.ip_address(hostname_clean)
        if not is_safe_ip(hostname_clean):
            return False, f"Hostname '{hostname_clean}' is a restricted or private IP address."
    except ValueError:
        # Not an IP literal, it's a domain name
        pass

    # Resolve DNS to check resulting IPs
    try:
        addr_info = socket.getaddrinfo(hostname_clean, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        for entry in addr_info:
            ip_addr = entry[4][0]
            if not is_safe_ip(ip_addr):
                return False, f"Hostname '{hostname_clean}' resolved to private/restricted IP '{ip_addr}'."
    except socket.gaierror:
        # Hostname could not be resolved in offline/sandbox environment; syntax is valid public domain
        pass
    except Exception as e:
        return False, f"SSRF security validation check failed: {str(e)}"

    return True, None

def resolve_redirects(
    url: str,
    max_redirects: int = 5,
    timeout: float = 3.5,
    user_agent: str = "Aegis-Quishing-Scanner/2.4 (Security Inspector)"
) -> Dict[str, Any]:
    """
    Safely resolves HTTP/HTTPS redirect chains for QR URLs with strict SSRF controls.
    Returns detailed redirect chain telemetry.
    """
    if not url or not isinstance(url, str):
        return {
            "original_url": "",
            "redirect_chain": [],
            "final_url": "",
            "redirect_count": 0,
            "resolution_success": False,
            "resolution_error": "Empty or non-string URL provided."
        }

    normalized_url = url.strip()
    if normalized_url in _RESOLUTION_CACHE:
        return _RESOLUTION_CACHE[normalized_url]

    chain: List[str] = [normalized_url]
    current_url = normalized_url
    redirect_count = 0
    error_msg: Optional[str] = None
    success = False

    session = requests.Session()
    session.headers.update({
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    while redirect_count < max_redirects:
        # Validate current hop against SSRF
        is_safe, ssrf_err = validate_url_for_ssrf(current_url)
        if not is_safe:
            error_msg = f"SSRF security restriction halted resolution: {ssrf_err}"
            break

        try:
            # Issue HEAD request first with short timeout to avoid large downloads
            resp = session.head(current_url, allow_redirects=False, timeout=timeout)
            
            # If server returns 405 Method Not Allowed for HEAD, fallback to GET with stream
            if resp.status_code == 405:
                resp = session.get(current_url, allow_redirects=False, stream=True, timeout=timeout)

            # Check if redirection response
            if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                next_url = resp.headers["Location"].strip()
                # Handle relative URLs
                next_url = urllib.parse.urljoin(current_url, next_url)
                
                # Prevent infinite redirection loops
                if next_url in chain:
                    error_msg = "Circular redirect loop detected."
                    break

                chain.append(next_url)
                current_url = next_url
                redirect_count += 1
            else:
                # Terminal destination reached
                success = True
                break

        except requests.Timeout:
            error_msg = f"Connection timed out after {timeout}s while resolving hop."
            break
        except requests.RequestException as e:
            error_msg = f"Network transport error: {str(e)}"
            break
        except Exception as e:
            error_msg = f"Unexpected error during redirect resolution: {str(e)}"
            break

    if redirect_count >= max_redirects and not success:
        error_msg = f"Exceeded maximum redirect limit ({max_redirects} hops)."

    # If the initial URL is safe and reached terminal hop or failed safely
    final_url = chain[-1]
    
    # If terminal status was reached without network crash
    if not error_msg:
        success = True

    result = {
        "original_url": normalized_url,
        "redirect_chain": chain,
        "final_url": final_url,
        "redirect_count": redirect_count,
        "resolution_success": success,
        "resolution_error": error_msg
    }

    # Store in memory cache
    if len(_RESOLUTION_CACHE) < MAX_CACHE_SIZE:
        _RESOLUTION_CACHE[normalized_url] = result

    return result

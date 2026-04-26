import socket
import ssl
import datetime

def check_ssl_expiry(hostname):
    context = ssl.create_default_context()
    try:
        # Connect to the target on port 443
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the certificate data
                cert = ssock.getpeercert()
                
                # Extract the expiration date
                expiry_str = cert['notAfter']
                expiry_date = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                
                # Calculate days remaining
                delta = expiry_date - datetime.datetime.utcnow()
                
                if delta.days <= 0:
                    return f"[!] ALERT: SSL for {hostname} is EXPIRED!"
                elif delta.days < 30:
                    return f"[!] WARNING: SSL for {hostname} expires in {delta.days} days."
                else:
                    return f"[+] SUCCESS: SSL is secure for another {delta.days} days."
    except Exception as e:
        return f"[?] ERROR: Could not reach {hostname} (Possible port 443 closure)."

# Test your prototype
target_site = "crony.com"
print(check_ssl_expiry(target_site))
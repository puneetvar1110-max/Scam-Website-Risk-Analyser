
import ipaddress
from urllib.parse import urlsplit

print("\n" + "=" * 48)
print("          SCAM WEBSITE RISK ANALYSER")
print("=" * 48)

risk = 0

url = input("\n[+] Enter Website URL: ").strip()

parsed_url = urlsplit(url)

if parsed_url.scheme in ("http", "https") and parsed_url.hostname:

    print("\n" + "-" * 48)
    print("                 SCAN DETAILS")
    print("-" * 48)

    print(f"Website URL : {url}")

    # Connection Security
    print("\n[1] CONNECTION SECURITY")

    if parsed_url.scheme == "https":
        print("    Status : HTTPS Enabled")
    else:
        print("    Status : HTTP (Not Encrypted)")
        risk += 20

    # URL Length
    print("\n[2] URL LENGTH ANALYSIS")

    lenurl = len(url)

    print(f"    Length : {lenurl} characters")

    if lenurl < 75:
        print("    Result : Normal")
    else:
        print("    Result : Suspicious URL Length")
        risk += 20

    # Suspicious Indicators
    print("\n[3] SUSPICIOUS INDICATORS")

    warning = {
        "login": 15,
        "bank": 25,
        "verify": 20,
        "@": 20,
        "fake": 20
    }

    show = False

    for i in warning:
        if i in url.lower():
            show = True
            print(f"    [!] {i} detected (+{warning[i]})")
            risk += warning[i]

    if show == False:
        print("    Result : No suspicious indicators")

    # IP Address Analysis
    print("\n[4] IP ADDRESS ANALYSIS")

    domain = parsed_url.hostname

    try:
        ip = ipaddress.ip_address(domain)

        print(f"    IP      : {ip}")

        if isinstance(ip, ipaddress.IPv4Address):
            print("    Type    : IPv4")
        elif isinstance(ip, ipaddress.IPv6Address):
            print("    Type    : IPv6")

        if ip.is_private:
            print("    Network : Private IP")
        else:
            print("    Network : Public IP")

        risk += 25

    except ValueError:
        print("    Result  : Normal Domain Name")

    # Final Result
    risk = min(risk, 100)

    print("\n" + "=" * 48)
    print("                  SCAN RESULT")
    print("=" * 48)

    print(f"\n    Risk Score : {risk}/100")

    if risk <= 20:
        level = "LOW"
        message = "No major warning indicators found."

    elif risk <= 50:
        level = "MEDIUM"
        message = "Some suspicious indicators detected."

    else:
        level = "HIGH"
        message = "Multiple suspicious indicators detected."

    print(f"    Risk Level : {level}")
    print(f"    Analysis   : {message}")

    print("\n" + "-" * 48)
    print("Note: This is a basic heuristic analysis.")
    print("It cannot guarantee website safety.")
    print("=" * 48)

else:
    print("\n[ERROR] Invalid URL!")
    print("Please enter a valid HTTP or HTTPS URL.")

import re
import sys
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


# ---------------------------------------------------------
# Suspicious keywords commonly found in phishing emails
# ---------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify your account",
    "account suspended",
    "password",
    "reset your password",
    "click here",
    "confirm your account",
    "login",
    "payment required",
    "invoice",
    "security alert",
    "unusual activity",
    "gift card",
    "wire transfer",
    "verify your identity",
    "immediately",
]


# ---------------------------------------------------------
# Extract URLs from email text
# ---------------------------------------------------------

def extract_urls(text):
    pattern = r"https?://[^\s<>\"]+"
    return re.findall(pattern, text, re.IGNORECASE)


# ---------------------------------------------------------
# Analyze URLs
# ---------------------------------------------------------

def analyze_urls(urls):
    suspicious = []

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        reasons = []

        # HTTP instead of HTTPS
        if parsed.scheme.lower() != "https":
            reasons.append("URL does not use HTTPS")

        # @ symbol can hide the actual destination
        if "@" in domain:
            reasons.append("URL contains @ character")

        # IP address instead of domain name
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            reasons.append(
                "URL uses an IP address instead of a domain"
            )

        # Very long URL
        if len(url) > 100:
            reasons.append("URL is unusually long")

        if reasons:
            suspicious.append({
                "url": url,
                "reasons": reasons
            })

    return suspicious


# ---------------------------------------------------------
# Analyze sender address and domain
# ---------------------------------------------------------

def analyze_sender(sender):
    findings = []
    score = 0

    # Extract email address
    match = re.search(
        r"[\w\.-]+@[\w\.-]+\.\w+",
        sender
    )

    if not match:
        findings.append(
            "Unable to extract a valid sender email address"
        )
        return score, findings

    email_address = match.group(0)
    domain = email_address.split("@")[-1].lower()

    findings.append(
        f"Sender domain identified: {domain}"
    )

    # IP address used as sender domain
    if re.match(
        r"^\d+\.\d+\.\d+\.\d+$",
        domain
    ):
        score += 20
        findings.append(
            "Sender uses an IP address instead of a domain"
        )

    # Suspicious terms in domain
    suspicious_domain_terms = [
        "verify",
        "secure",
        "account",
        "login",
        "support",
        "security",
        "update"
    ]

    matched_terms = [
        term
        for term in suspicious_domain_terms
        if term in domain
    ]

    if matched_terms:
        score += 10
        findings.append(
            "Sender domain contains potentially suspicious "
            "terms: " + ", ".join(matched_terms)
        )

    # Very long domain
    if len(domain) > 40:
        score += 10
        findings.append(
            "Sender domain is unusually long"
        )

    return score, findings


# ---------------------------------------------------------
# Extract email body
# ---------------------------------------------------------

def extract_body(message):
    body = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass

    else:
        try:
            body = message.get_content()
        except Exception:
            body = ""

    return body


# ---------------------------------------------------------
# Detect attachments
# ---------------------------------------------------------

def analyze_attachments(message):
    attachments = []

    for part in message.walk():

        filename = part.get_filename()

        if filename:
            attachments.append(filename)

    return attachments


# ---------------------------------------------------------
# Analyze authentication results
# ---------------------------------------------------------

def analyze_authentication(auth_results):
    score = 0
    findings = []

    auth_lower = auth_results.lower()

    if "spf=fail" in auth_lower:
        score += 25
        findings.append(
            "SPF authentication failed"
        )

    elif "spf=pass" in auth_lower:
        findings.append(
            "SPF authentication passed"
        )

    if "dkim=fail" in auth_lower:
        score += 25
        findings.append(
            "DKIM authentication failed"
        )

    elif "dkim=pass" in auth_lower:
        findings.append(
            "DKIM authentication passed"
        )

    if "dmarc=fail" in auth_lower:
        score += 25
        findings.append(
            "DMARC authentication failed"
        )

    elif "dmarc=pass" in auth_lower:
        findings.append(
            "DMARC authentication passed"
        )

    return score, findings


# ---------------------------------------------------------
# Analyze suspicious keywords
# ---------------------------------------------------------

def analyze_keywords(text):
    matched_keywords = []

    text_lower = text.lower()

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword.lower() in text_lower:
            matched_keywords.append(keyword)

    score = 0
    findings = []

    if matched_keywords:

        # Maximum 25 points from keywords
        score = min(
            len(matched_keywords) * 5,
            25
        )

        findings.append(
            "Suspicious keywords detected: "
            + ", ".join(matched_keywords)
        )

    return score, findings


# ---------------------------------------------------------
# Main email analysis
# ---------------------------------------------------------

def analyze_email(file_path):

    # Read email
    try:

        with open(file_path, "rb") as file:

            message = BytesParser(
                policy=policy.default
            ).parse(file)

    except FileNotFoundError:

        print(
            f"\nError: Email file not found: {file_path}"
        )

        return

    except Exception as error:

        print(
            f"\nError reading email: {error}"
        )

        return

    # Basic headers
    sender = message.get(
        "From",
        "Unknown"
    )

    subject = message.get(
        "Subject",
        "No subject"
    )

    auth_results = message.get(
        "Authentication-Results",
        ""
    )

    # Extract body
    body = extract_body(message)

    # Combined text for keyword analysis
    combined_text = (
        f"{subject} {body}"
    )

    # -----------------------------------------------------
    # Risk score starts at zero
    # -----------------------------------------------------

    total_score = 0

    findings = []

    # -----------------------------------------------------
    # Sender analysis
    # -----------------------------------------------------

    sender_score, sender_findings = analyze_sender(
        sender
    )

    total_score += sender_score
    findings.extend(sender_findings)

    # -----------------------------------------------------
    # Authentication analysis
    # -----------------------------------------------------

    auth_score, auth_findings = analyze_authentication(
        auth_results
    )

    total_score += auth_score
    findings.extend(auth_findings)

    # -----------------------------------------------------
    # Keyword analysis
    # -----------------------------------------------------

    keyword_score, keyword_findings = analyze_keywords(
        combined_text
    )

    total_score += keyword_score
    findings.extend(keyword_findings)

    # -----------------------------------------------------
    # URL analysis
    # -----------------------------------------------------

    urls = extract_urls(body)

    suspicious_urls = analyze_urls(urls)

    if suspicious_urls:

        url_score = min(
            len(suspicious_urls) * 10,
            20
        )

        total_score += url_score

        findings.append(
            f"{len(suspicious_urls)} suspicious URL(s) detected"
        )

    # -----------------------------------------------------
    # Attachment analysis
    # -----------------------------------------------------

    attachments = analyze_attachments(
        message
    )

    if attachments:

        total_score += min(
            len(attachments) * 10,
            20
        )

        findings.append(
            "Attachment(s) detected: "
            + ", ".join(attachments)
        )

    # -----------------------------------------------------
    # HTML email detection
    # -----------------------------------------------------

    html_detected = False

    for part in message.walk():

        if part.get_content_type() == "text/html":

            html_detected = True
            break

    if html_detected:

        findings.append(
            "HTML content detected in email"
        )

    # -----------------------------------------------------
    # Limit score to 100
    # -----------------------------------------------------

    total_score = min(
        total_score,
        100
    )

    # -----------------------------------------------------
    # Classification
    # -----------------------------------------------------

    if total_score >= 50:

        classification = (
            "HIGH RISK - Likely Phishing"
        )

    elif total_score >= 25:

        classification = (
            "MEDIUM RISK - Suspicious"
        )

    else:

        classification = (
            "LOW RISK - No Strong Phishing Indicators"
        )

    # -----------------------------------------------------
    # Display results
    # -----------------------------------------------------

    print("\n")
    print("=" * 65)
    print("                 AI EMAIL ANALYZER")
    print("=" * 65)

    print("\n[EMAIL INFORMATION]")

    print(f"From       : {sender}")
    print(f"Subject    : {subject}")

    print("\n[AUTHENTICATION RESULTS]")

    if auth_results:

        print(auth_results)

    else:

        print(
            "Authentication-Results header not available"
        )

    print("\n[URL ANALYSIS]")

    if urls:

        for url in urls:

            print(
                f" - {url}"
            )

    else:

        print("No URLs detected")

    print("\n[ATTACHMENT ANALYSIS]")

    if attachments:

        for attachment in attachments:

            print(
                f" - {attachment}"
            )

    else:

        print("No attachments detected")

    print("\n[SECURITY FINDINGS]")

    if findings:

        for finding in findings:

            print(
                f" - {finding}"
            )

    else:

        print(
            "No major security indicators detected"
        )

    print("\n[RESULT]")

    print(
        f"Risk Score  : {total_score}/100"
    )

    print(
        f"Classification: {classification}"
    )

    print("=" * 65)

    print(
        "\nNote: This tool provides automated triage assistance."
    )

    print(
        "Final phishing determination should be performed by"
        " a security analyst."
    )

    print()


# ---------------------------------------------------------
# Program entry point
# ---------------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "\nUsage:"
        )

        print(
            "python src\\email_analyzer.py "
            "samples\\sample_phishing.eml"
        )

        sys.exit(1)

    email_file = sys.argv[1]

    analyze_email(email_file)
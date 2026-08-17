# AI Email Analyzer — Project Report

## 1. Project Overview

The AI Email Analyzer is a Python-based cybersecurity tool designed to assist with first-level phishing email triage.

The analyzer examines email headers, sender information, authentication results, message content, URLs, and attachments to identify indicators commonly associated with phishing and social engineering attacks.

The tool assigns a risk score and classifies the email as Low Risk, Medium Risk, or High Risk.

## 2. Objectives

* Analyze suspicious email headers.
* Inspect SPF, DKIM, and DMARC authentication results.
* Analyze sender email addresses and domains.
* Detect suspicious phishing-related keywords.
* Extract URLs from email content.
* Identify potentially suspicious URLs.
* Detect email attachments.
* Generate a risk score.
* Provide an automated first-level phishing classification.

## 3. Technologies Used

* Python
* Python Email Library
* Regular Expressions
* URL Parsing
* NLP/Keyword Analysis Concepts
* Email Header Analysis
* SPF
* DKIM
* DMARC

## 4. Detection Workflow

```text
Email (.eml)
     |
     v
Header Extraction
     |
     +----> Sender / Domain Analysis
     |
     +----> SPF / DKIM / DMARC
     |
     +----> Keyword Analysis
     |
     +----> URL Analysis
     |
     +----> Attachment Detection
     |
     v
Risk Scoring
     |
     v
Email Classification
```

## 5. Test Cases

### Test Case 1 — Synthetic Phishing Email

**File:**

`sample_phishing.eml`

The test email contains multiple simulated phishing indicators, including:

* Urgent language
* Account verification request
* Password-related language
* Failed SPF authentication
* Failed DKIM authentication
* Failed DMARC authentication
* HTTP URL
* Suspicious keywords

**Expected classification:**

High Risk — Likely Phishing

**Evidence:**

`screenshots/phishing-analysis.png`

---

### Test Case 2 — Email With Attachment

**File:**

`sample_attachment.eml`

The test email was designed to verify that the analyzer can detect email attachments.

The message contains:

`security_update.txt`

The analyzer identifies the attachment and includes it as part of the risk assessment.

**Evidence:**

`screenshots/attachment-analysis.png`

---

### Test Case 3 — Normal Email

**File:**

`sample_normal.eml`

This test represents a normal project-related email.

The message contains:

* No suspicious URLs
* No attachments
* SPF pass
* DKIM pass
* DMARC pass
* No strong phishing-related keywords

**Expected classification:**

Low Risk — No Strong Phishing Indicators

**Evidence:**

`screenshots/normal-email-analysis.png`

## 6. Risk Scoring

The analyzer uses an indicator-based scoring approach.

Examples of indicators include:

| Indicator                         | Example Score |
| --------------------------------- | ------------: |
| SPF failure                       |           +25 |
| DKIM failure                      |           +25 |
| DMARC failure                     |           +25 |
| Suspicious keywords               |     Up to +25 |
| Suspicious URL                    |     Up to +20 |
| Attachment detected               |     Up to +20 |
| Suspicious sender characteristics |      Variable |

The final score is limited to a maximum of 100.

### Classification

* **0–24:** Low Risk
* **25–49:** Medium Risk
* **50–100:** High Risk

These thresholds are intended for demonstration and first-level triage rather than definitive malware or phishing detection.

## 7. Security Findings

The analyzer demonstrates how multiple weak indicators can be combined to prioritize suspicious emails.

For example, an email containing authentication failures, urgent language, suspicious URLs, and credential-related keywords receives a higher risk score than a normal email with successful authentication results.

## 8. Limitations

The analyzer is a triage tool and does not replace a human security analyst.

Limitations include:

* Keyword matches can produce false positives.
* Domain names cannot be considered malicious based only on their appearance.
* SPF, DKIM, and DMARC results require contextual interpretation.
* URL analysis does not determine whether a website is actually malicious.
* Attachment detection does not mean an attachment is malicious.
* The current scoring system is rule-based rather than a trained machine-learning model.

## 9. Future Improvements

Potential improvements include:

* Machine-learning-based phishing classification
* Better sender-domain reputation analysis
* WHOIS/domain-age analysis
* URL reputation checking
* Threat-intelligence API integration
* Attachment hash analysis
* Malware sandbox integration
* Improved NLP-based text classification
* HTML and JavaScript analysis
* Automated PDF/HTML reporting

## 10. Skills Demonstrated

* Python programming
* Email security
* Phishing analysis
* Email header analysis
* SPF/DKIM/DMARC
* Security automation
* URL analysis
* Risk scoring
* Cybersecurity documentation
* Security triage

## 11. Conclusion

The AI Email Analyzer demonstrates a practical approach to automating first-level phishing email triage.

By combining sender analysis, email authentication results, content analysis, URL inspection, and attachment detection, the tool can prioritize suspicious emails for further investigation.

The project demonstrates how Python can be applied to automate repetitive cybersecurity analysis tasks.

## 12. Disclaimer

All test emails used in this project are synthetic and were created for educational purposes.

The analyzer is intended for defensive cybersecurity research and first-level email triage. It should not be treated as a definitive determination that an email or attachment is malicious.

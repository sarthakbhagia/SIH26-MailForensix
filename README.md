# MailForensix 📧🔍

**MailForensix** is an intelligent, automated email forensics and phishing analysis tool developed for **Smart India Hackathon 2026 (SIH '26)**. It simplifies digital forensics for cybersecurity investigators, security operation center (SOC) analysts, and law enforcement agencies by analyzing email headers, artifacts, links, attachments, and metadata to detect phishing attempts, header spoofing, and malicious intent.

---

## 🎯 Core Idea

Email is one of the most common vectors for cyberattacks, social engineering, and financial fraud. Manual header and attachment analysis is time-consuming and requires specialized expertise. 

**MailForensix** automates end-to-end email forensic analysis:
1. **Header & Authentication Verification**: Parses raw `.eml` / `.msg` files to extract SPF, DKIM, DMARC records, and hop-by-hop IP routing trails to spot spoofed domain signatures.
2. **Body & Link Inspection**: Scans embedded URLs, checks domain reputation against threat intelligence feeds, and identifies phishing tactics (e.g., typosquatting, IDN homograph attacks).
3. **Attachment & Artifact Analysis**: Extracts, hashes (MD5, SHA-256), and evaluates attachments for malicious payloads.
4. **Automated Reporting**: Generates comprehensive forensic evidence reports with risk scoring for legal and technical compliance.

---

## 🛠️ Tech Stack

- **Frontend / UI**: React.js / Next.js, Tailwind CSS *(or Streamlit for quick prototyping)*
- **Backend**: Python (FastAPI / Flask)
- **Forensic & Parsing Libraries**:
  - `python-mail-parser` / `extract-msg`: Email parsing and attachment extraction
  - `dnspython`: DNS, SPF, DKIM, and DMARC verification
  - `ipwhois` / `geoip2`: IP geolocation and ISP routing analysis
  - `re` / `BeautifulSoup4`: URL extraction and DOM scraping
- **Threat Intelligence Integrations**:
  - VirusTotal API
  - AbuseIPDB API
  - PhishTank API
- **Database**: PostgreSQL / MongoDB *(for case history and analysis caching)*

---

## 📂 Project Structure

```text
SIH26-MailForensix/
├── backend/
│   ├── app/
│   │   ├── api/             # API routes and endpoint controllers
│   │   ├── core/            # Configs, security, and global variables
│   │   ├── parsers/         # Email header, body, and attachment parsers
│   │   ├── services/        # Threat Intel API integrations (VirusTotal, AbuseIPDB)
│   │   └── utils/           # Helper functions, hashing, IP lookup scripts
│   ├── tests/               # Unit and integration test cases
│   ├── requirements.txt     # Python dependencies
│   └── main.py              # Application entry point
│
├── frontend/
│   ├── public/              # Static assets and icons
│   ├── src/
│   │   ├── components/      # Reusable UI components (Header viewer, Map, Risk score)
│   │   ├── pages/           # Dashboard, Upload, and Report views
│   │   └── services/        # API calls to backend
│   └── package.json         # Frontend dependencies
│
├── sample_emails/           # Sample .eml / .msg test files for demo
├── docs/                    # Architecture diagrams and SIH presentation materials
├── LICENSE                  # Open-source license
└── README.md                # Project documentation

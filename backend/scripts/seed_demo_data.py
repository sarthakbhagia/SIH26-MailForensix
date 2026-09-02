"""MailForensix - Hackathon Demo Data Seeding & Reset Script.

This script safely clears existing demo/analysis data while preserving
user authentication and organization records, then seeds a coherent,
diverse, and realistic 36-artifact dataset spanning:
  - 20 LEGITIMATE records (internal comms, invoices, meeting invites, newsletters)
  - 7 SUSPICIOUS records (anomalous hops, untrusted TLDs, external contact changes)
  - 5 PHISHING records (M365 credential harvesting, HR direct deposit, DocuSign lookalike)
  - 4 BEC/FRAUD records (CEO wire fraud, executive payroll change, vendor invoice routing)

It seeds complete ML ensemble results, header forensics, MTA relay paths,
geolocation coordinates, IOCs, 3 active investigation cases, and 4 unack triage alerts.

Usage:
    python backend/scripts/seed_demo_data.py --confirm
"""

import argparse
import asyncio
import hashlib
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

# Setup Python path
CURRENT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = CURRENT_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, Base, engine
from app.models.alert import Alert, AlertSeverity
from app.models.analysis_result import AnalysisResult
from app.models.audit_log import AuditLog
from app.models.email_case import Case, CaseEmail, CaseNote, CaseSeverity, CaseStatus, Email, EmailStatus
from app.models.organization import Organization
from app.models.user import User, UserRole
from app.core.security import get_password_hash

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_demo")


def compute_hashes(raw_bytes: bytes) -> dict:
    return {
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "sha1": hashlib.sha1(raw_bytes).hexdigest(),
        "md5": hashlib.md5(raw_bytes).hexdigest(),
    }


# ==============================================================================
# DEMO DATASET DEFINITIONS (36 Realistic Records)
# ==============================================================================

DEMO_RECORDS = [
    # --------------------------------------------------------------------------
    # A. LEGITIMATE RECORDS (20 items, Scores 5.0 - 22.0, Tier: Low <= 25)
    # --------------------------------------------------------------------------
    {
        "id": "11111111-0001-4000-8000-000000000001",
        "sender": "Satya Nadella <ceo-office@enterprise-corp.com>",
        "recipients": ["all-staff@enterprise-corp.com"],
        "subject": "Q3 Financial Performance & Town Hall Meeting Schedule",
        "body_text": "Team,\n\nPlease join us this Thursday at 3:00 PM EST for our global Q3 all-hands meeting. We will review our quarterly product milestones and financial results.\n\nBest regards,\nExecutive Office",
        "days_ago": 6,
        "label": "LEGITIMATE",
        "confidence": 0.98,
        "score": 6.5,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.12", "US", "Redmond", 47.674, -122.121, "Microsoft Azure")],
        "urls": ["https://portal.enterprise-corp.com/townhall"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0002-4000-8000-000000000002",
        "sender": "AWS Billing <no-reply-aws@amazon.com>",
        "recipients": ["finance@enterprise-corp.com", "devops@enterprise-corp.com"],
        "subject": "Amazon Web Services Invoice #INV-2026-8841 Summary",
        "body_text": "Your AWS monthly billing statement for the period ending August 31, 2026 is now available. Total amount charged: $14,289.42 USD. Log into AWS Console to download the detailed itemized PDF.",
        "days_ago": 5,
        "label": "LEGITIMATE",
        "confidence": 0.97,
        "score": 8.0,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("54.240.27.1", "US", "Seattle", 47.606, -122.332, "Amazon AWS")],
        "urls": ["https://console.aws.amazon.com/billing/home"],
        "domain": "amazon.com",
    },
    {
        "id": "11111111-0003-4000-8000-000000000003",
        "sender": "People Operations <hr-benefits@enterprise-corp.com>",
        "recipients": ["employees@enterprise-corp.com"],
        "subject": "Updated Health Benefits & Annual Open Enrollment Guide",
        "body_text": "Hi everyone,\n\nAnnual open enrollment for employee medical, dental, and vision insurance begins next Monday. Review the benefits handbook on the internal wiki before October 15th.",
        "days_ago": 5,
        "label": "LEGITIMATE",
        "confidence": 0.96,
        "score": 5.0,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.15", "US", "New York", 40.712, -74.006, "Corporate Cloud MTA")],
        "urls": ["https://intranet.enterprise-corp.com/benefits/2026"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0004-4000-8000-000000000004",
        "sender": "Engineering Lead <alex.chen@enterprise-corp.com>",
        "recipients": ["frontend-team@enterprise-corp.com"],
        "subject": "Sprint 42 Architecture Review & Design Decisions",
        "body_text": "Hey team,\n\nNotes from today's retro: We approved the migration to TanStack Query v5 and verified the dark-mode cyber palette. Pull request #304 is ready for peer review.",
        "days_ago": 5,
        "label": "LEGITIMATE",
        "confidence": 0.95,
        "score": 7.2,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.18", "US", "San Francisco", 37.774, -122.419, "Fastly CDN / MTA")],
        "urls": ["https://github.com/enterprise/forensix/pull/304"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0005-4000-8000-000000000005",
        "sender": "IT Compliance <infosec@enterprise-corp.com>",
        "recipients": ["all-users@enterprise-corp.com"],
        "subject": "Scheduled Security Patching & Maintenance Window",
        "body_text": "Please be advised that core network switches and VPN gateways will undergo rolling security patches this Sunday between 02:00 - 04:00 UTC. No user action required.",
        "days_ago": 4,
        "label": "LEGITIMATE",
        "confidence": 0.94,
        "score": 10.5,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.20", "US", "Chicago", 41.878, -87.629, "Internal Mail Relay")],
        "urls": ["https://status.enterprise-corp.com"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0006-4000-8000-000000000006",
        "sender": "GitHub Enterprise <notifications@github.com>",
        "recipients": ["devs@enterprise-corp.com"],
        "subject": "Repository Security Advisory: Dependabot alert resolved",
        "body_text": "Dependabot has verified that vulnerability CVE-2026-2144 in dependency 'aiohttp' was patched in commit 9d821e on main branch. All CI security checks passing.",
        "days_ago": 4,
        "label": "LEGITIMATE",
        "confidence": 0.97,
        "score": 9.0,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("140.82.112.1", "US", "San Francisco", 37.774, -122.419, "GitHub Mail Relay")],
        "urls": ["https://github.com/advisories/GHSA-2026-xxxx"],
        "domain": "github.com",
    },
    {
        "id": "11111111-0007-4000-8000-000000000007",
        "sender": "Finance Department <payroll-services@enterprise-corp.com>",
        "recipients": ["advait@enterprise-corp.com"],
        "subject": "Monthly Paystub Available - August 2026",
        "body_text": "Your electronic paystub for pay period ending 31-Aug-2026 is now available for viewing on the secure internal employee intranet portal.",
        "days_ago": 4,
        "label": "LEGITIMATE",
        "confidence": 0.93,
        "score": 8.5,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.12", "US", "Austin", 30.267, -97.743, "ADP / Corporate MTA")],
        "urls": ["https://hr.enterprise-corp.com/paystubs"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0008-4000-8000-000000000008",
        "sender": "Zoom Notifications <no-reply@zoom.us>",
        "recipients": ["sarah.jenkins@enterprise-corp.com"],
        "subject": "Cloud Recording: Sprint 42 Planning Video Available",
        "body_text": "Your cloud recording from Sprint 42 Planning is now processed and available to view or share with authenticated team members.",
        "days_ago": 3,
        "label": "LEGITIMATE",
        "confidence": 0.96,
        "score": 6.0,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("52.202.12.8", "US", "Ashburn", 39.043, -77.487, "Zoom Video Comm")],
        "urls": ["https://zoom.us/rec/share/982341"],
        "domain": "zoom.us",
    },
    {
        "id": "11111111-0009-4000-8000-000000000009",
        "sender": "Customer Success <cs-updates@enterprise-corp.com>",
        "recipients": ["account-managers@enterprise-corp.com"],
        "subject": "Weekly Customer Retention & NPS Performance Report",
        "body_text": "Great news: Our Net Promoter Score rose to +68 this week following the release of the automated relay tracing engine. Attached are customer verbatim reviews.",
        "days_ago": 3,
        "label": "LEGITIMATE",
        "confidence": 0.95,
        "score": 7.0,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.14", "US", "Boston", 42.360, -71.058, "Corporate MTA")],
        "urls": ["https://analytics.enterprise-corp.com/nps"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0010-4000-8000-000000000010",
        "sender": "DevOps Operations <pagerduty@enterprise-corp.com>",
        "recipients": ["sre-team@enterprise-corp.com"],
        "subject": "Cluster Health: Kubernetes node pool scale-down complete",
        "body_text": "Auto-scaler safely drained and terminated 4 idle worker nodes in us-east-1 following peak processing hours. CPU utilization nominal at 34%.",
        "days_ago": 3,
        "label": "LEGITIMATE",
        "confidence": 0.94,
        "score": 11.2,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.16", "US", "Denver", 39.739, -104.990, "Kubernetes Ingress MTA")],
        "urls": ["https://grafana.enterprise-corp.com/d/k8s"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0011-4000-8000-000000000011",
        "sender": "Legal Team <legal@enterprise-corp.com>",
        "recipients": ["management@enterprise-corp.com"],
        "subject": "Corporate Policy Update: Generative AI Usage Guidelines",
        "body_text": "Please review the updated policy on commercial LLM API integrations and confidential customer data retention. Compliance sign-off required by end of month.",
        "days_ago": 2,
        "label": "LEGITIMATE",
        "confidence": 0.96,
        "score": 8.0,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.12", "US", "Washington DC", 38.907, -77.036, "Corporate MTA")],
        "urls": ["https://intranet.enterprise-corp.com/legal/ai-policy-2026"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0012-4000-8000-000000000012",
        "sender": "Travel Desk <concur-travel@enterprise-corp.com>",
        "recipients": ["advait@enterprise-corp.com"],
        "subject": "Travel Approval: Black Hat USA Conference Itinerary Confirmed",
        "body_text": "Your travel request and hotel booking for Black Hat USA has been authorized by your manager. Booking confirmation code: BH-99421-LV.",
        "days_ago": 2,
        "label": "LEGITIMATE",
        "confidence": 0.97,
        "score": 6.8,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.15", "US", "Dallas", 32.776, -96.797, "Concur MTA")],
        "urls": ["https://concur.enterprise-corp.com/itinerary/BH99421"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0013-4000-8000-000000000013",
        "sender": "Tech Support <helpdesk@enterprise-corp.com>",
        "recipients": ["staff@enterprise-corp.com"],
        "subject": "Resolved Ticket #48291: Conference Room A/V Calibration",
        "body_text": "The display sync and microphone feedback issues in Conference Room 4B have been resolved. Microphones have been re-calibrated.",
        "days_ago": 2,
        "label": "LEGITIMATE",
        "confidence": 0.95,
        "score": 5.2,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.18", "US", "Seattle", 47.606, -122.332, "Jira Service Desk MTA")],
        "urls": ["https://jira.enterprise-corp.com/browse/HD-48291"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0014-4000-8000-000000000014",
        "sender": "UX Design <design@enterprise-corp.com>",
        "recipients": ["ui-leads@enterprise-corp.com"],
        "subject": "Design System v3.2 Component Tokens Ready for Review",
        "body_text": "The high-contrast cyber telemetry widgets and font tokens are updated in Figma. Check out the component library page before sprint handoff.",
        "days_ago": 2,
        "label": "LEGITIMATE",
        "confidence": 0.96,
        "score": 6.1,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.22", "US", "San Jose", 37.338, -121.886, "Figma Webhook / MTA")],
        "urls": ["https://figma.com/@enterprise/design-system-v3"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0015-4000-8000-000000000015",
        "sender": "Marketing Team <newsletter@tech-briefing.io>",
        "recipients": ["subscribers@enterprise-corp.com"],
        "subject": "This Week in Security: Graph Neural Networks in Threat Hunting",
        "body_text": "Edition #148: How modern DFIR platforms combine graph centrality metrics with transformer embeddings to uncover APT lateral movement. Read the full issue.",
        "days_ago": 1,
        "label": "LEGITIMATE",
        "confidence": 0.92,
        "score": 14.5,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("192.0.2.140", "US", "Atlanta", 33.749, -84.388, "MailChimp Delivery MTA")],
        "urls": ["https://tech-briefing.io/issue/148"],
        "domain": "tech-briefing.io",
    },
    {
        "id": "11111111-0016-4000-8000-000000000016",
        "sender": "Research & Development <dr.aravind@enterprise-corp.com>",
        "recipients": ["ai-lab@enterprise-corp.com"],
        "subject": "Paper Draft: Fast Header Parsing in Asynchronous Pipelines",
        "body_text": "Attached is the pre-print draft for the upcoming IEEE Symposium on Forensic Computing. Please send feedback on Section 4 (MTA graph triangulation).",
        "days_ago": 1,
        "label": "LEGITIMATE",
        "confidence": 0.97,
        "score": 9.2,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.12", "US", "Redmond", 47.674, -122.121, "Corporate MTA")],
        "urls": ["https://arxiv.org/abs/2026.xxxxx"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0017-4000-8000-000000000017",
        "sender": "Facilities Operations <facilities@enterprise-corp.com>",
        "recipients": ["campus-staff@enterprise-corp.com"],
        "subject": "Campus EV Charging Station Installation Complete",
        "body_text": "Eight Level 2 electric vehicle chargers are now live in the West Parking Deck. Charging is complimentary for employees using their badge tap.",
        "days_ago": 1,
        "label": "LEGITIMATE",
        "confidence": 0.98,
        "score": 5.0,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.15", "US", "Chicago", 41.878, -87.629, "Internal MTA")],
        "urls": ["https://facilities.enterprise-corp.com/ev-charging"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0018-4000-8000-000000000018",
        "sender": "Talent Acquisition <recruiting@enterprise-corp.com>",
        "recipients": ["hiring-managers@enterprise-corp.com"],
        "subject": "Candidate Interview Schedule: Senior Threat Researcher",
        "body_text": "Candidate Maya Patel is confirmed for round 2 technical interviews this Wednesday. Panel interviewers please review her GitHub portfolio.",
        "days_ago": 0,
        "label": "LEGITIMATE",
        "confidence": 0.95,
        "score": 7.8,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.18", "US", "New York", 40.712, -74.006, "Greenhouse ATS MTA")],
        "urls": ["https://greenhouse.io/enterprise/candidate/44910"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0019-4000-8000-000000000019",
        "sender": "Security Operations <soc-brief@enterprise-corp.com>",
        "recipients": ["soc-team@enterprise-corp.com"],
        "subject": "Daily Threat Intelligence Digest - September 02, 2026",
        "body_text": "Daily summary: Zero unauthorized breaches detected across firewall perimeters. Ingestion queues operating with 99.98% uptime.",
        "days_ago": 0,
        "label": "LEGITIMATE",
        "confidence": 0.96,
        "score": 8.5,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.12", "US", "San Francisco", 37.774, -122.419, "SOC Internal MTA")],
        "urls": ["https://soc.enterprise-corp.com/briefings/20260902"],
        "domain": "enterprise-corp.com",
    },
    {
        "id": "11111111-0020-4000-8000-000000000020",
        "sender": "Cloud Architecture <cloud-leads@enterprise-corp.com>",
        "recipients": ["arch-review@enterprise-corp.com"],
        "subject": "Database Read-Replica Topology Architecture Document",
        "body_text": "Attached is the revised PostgreSQL HA topology document featuring PgBouncer pooling and read replicas for forensic query workloads.",
        "days_ago": 0,
        "label": "LEGITIMATE",
        "confidence": 0.96,
        "score": 7.0,
        "severity": "low",
        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "relay_ips": [("198.51.100.15", "US", "Austin", 30.267, -97.743, "Corporate MTA")],
        "urls": ["https://wiki.enterprise-corp.com/db-topology"],
        "domain": "enterprise-corp.com",
    },

    # --------------------------------------------------------------------------
    # B. SUSPICIOUS RECORDS (7 items, Scores 28.0 - 48.0, Tier: Medium 26 - 50)
    # --------------------------------------------------------------------------
    {
        "id": "22222222-0001-4000-8000-000000000001",
        "sender": "Express Delivery Dispatch <tracking-notify@speed-courier-intl.xyz>",
        "recipients": ["logistics@enterprise-corp.com"],
        "subject": "Delivery Exception Notice: Parcel Tracking #US-8849-CL",
        "body_text": "Your package delivery could not be completed due to missing customs invoice details. Please update your delivery preferences within 48 hours to prevent return to sender.",
        "days_ago": 4,
        "label": "SUSPICIOUS",
        "confidence": 0.74,
        "score": 38.0,
        "severity": "medium",
        "auth": {"spf": "neutral", "dkim": "none", "dmarc": "none"},
        "relay_ips": [
            ("185.220.101.4", "NL", "Amsterdam", 52.367, 4.904, "Tor Exit / Unregistered Host"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://speed-courier-intl.xyz/track/exception?id=US8849"],
        "domain": "speed-courier-intl.xyz",
    },
    {
        "id": "22222222-0002-4000-8000-000000000002",
        "sender": "Accounting Vendor Update <billing-dept@acme-parts-corp.net>",
        "recipients": ["accounts-payable@enterprise-corp.com"],
        "subject": "Action Required: Annual Confirmation of Vendor Remittance Contacts",
        "body_text": "Dear customer,\n\nWe are conducting our annual accounting audit. Please verify your billing contact email and verify our vendor master file via the form attached.",
        "days_ago": 3,
        "label": "SUSPICIOUS",
        "confidence": 0.68,
        "score": 34.5,
        "severity": "medium",
        "auth": {"spf": "softfail", "dkim": "none", "dmarc": "none"},
        "relay_ips": [
            ("194.26.29.110", "RU", "Saint Petersburg", 59.934, 30.335, "VDSina Hosting"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://acme-parts-corp.net/verify-contact-audit"],
        "domain": "acme-parts-corp.net",
    },
    {
        "id": "22222222-0003-4000-8000-000000000003",
        "sender": "Cloud Storage Quota <alerts@storage-quota-system.top>",
        "recipients": ["storage-admin@enterprise-corp.com"],
        "subject": "Storage Notice: Your corporate shared drive has exceeded 95% capacity",
        "body_text": "Your account drive is nearing capacity limits. Temporary expansion has been provisioned. Click here to manage file retention quotas or request permanent allocation.",
        "days_ago": 3,
        "label": "SUSPICIOUS",
        "confidence": 0.72,
        "score": 42.0,
        "severity": "medium",
        "auth": {"spf": "neutral", "dkim": "none", "dmarc": "none"},
        "relay_ips": [
            ("91.240.118.50", "DE", "Frankfurt", 50.110, 8.682, "Hetzner Cloud"),
            ("198.51.100.12", "US", "Chicago", 41.878, -87.629, "Corporate Ingress"),
        ],
        "urls": ["http://storage-quota-system.top/drive/expand"],
        "domain": "storage-quota-system.top",
    },
    {
        "id": "22222222-0004-4000-8000-000000000004",
        "sender": "Project File Share <external-share@quick-files-share.org>",
        "recipients": ["engineering@enterprise-corp.com"],
        "subject": "Shared Document: 'Q4 Budget & Contractor Allocation.xlsx'",
        "body_text": "A contractor has shared a spreadsheet with your team. Access requires browser verification via the link below before the 72-hour link expiry.",
        "days_ago": 2,
        "label": "SUSPICIOUS",
        "confidence": 0.65,
        "score": 36.0,
        "severity": "medium",
        "auth": {"spf": "softfail", "dkim": "none", "dmarc": "neutral"},
        "relay_ips": [
            ("195.123.245.8", "NL", "Rotterdam", 51.924, 4.477, "Hostkey B.V."),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://quick-files-share.org/dl?id=992841"],
        "domain": "quick-files-share.org",
    },
    {
        "id": "22222222-0005-4000-8000-000000000005",
        "sender": "Telecom Voicemail System <voicemail-service@cloud-pbx-audio.cc>",
        "recipients": ["sales@enterprise-corp.com"],
        "subject": "New PBX Voicemail Message Received (42 seconds) from unknown caller",
        "body_text": "You received a new voicemail on extension 104. Click to listen to the audio transcript online or download the message player plugin.",
        "days_ago": 2,
        "label": "SUSPICIOUS",
        "confidence": 0.76,
        "score": 45.5,
        "severity": "medium",
        "auth": {"spf": "none", "dkim": "none", "dmarc": "none"},
        "relay_ips": [
            ("194.87.147.20", "RU", "Moscow", 55.755, 37.617, "Rostelecom"),
            ("198.51.100.12", "US", "Dallas", 32.776, -96.797, "Corporate Ingress"),
        ],
        "urls": ["http://cloud-pbx-audio.cc/voicemail/listen?msg=9941"],
        "domain": "cloud-pbx-audio.cc",
    },
    {
        "id": "22222222-0006-4000-8000-000000000006",
        "sender": "Global Cyber Defense Summit <registration@cyber-events-portal.info>",
        "recipients": ["ciso@enterprise-corp.com", "infosec@enterprise-corp.com"],
        "subject": "Complimentary Executive Pass: Global Threat Defense 2026",
        "body_text": "We have reserved 2 complimentary delegate tickets for Enterprise Corp leadership. Confirm attendance by clicking your individualized ticket voucher link.",
        "days_ago": 1,
        "label": "SUSPICIOUS",
        "confidence": 0.62,
        "score": 31.0,
        "severity": "medium",
        "auth": {"spf": "pass", "dkim": "none", "dmarc": "none"},
        "relay_ips": [
            ("185.196.10.82", "DE", "Munich", 48.135, 11.582, "Contabo GmbH"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://cyber-events-portal.info/voucher/claim?token=exec"],
        "domain": "cyber-events-portal.info",
    },
    {
        "id": "22222222-0007-4000-8000-000000000007",
        "sender": "HR Survey System <feedback@pulse-surveys-online.biz>",
        "recipients": ["employees@enterprise-corp.com"],
        "subject": "Mandatory 3-Minute Employee Workplace Sentiment Survey",
        "body_text": "Your feedback shapes our workplace. All responses are 100% anonymous. Click the survey token below to complete before Friday.",
        "days_ago": 1,
        "label": "SUSPICIOUS",
        "confidence": 0.70,
        "score": 35.0,
        "severity": "medium",
        "auth": {"spf": "neutral", "dkim": "none", "dmarc": "none"},
        "relay_ips": [
            ("185.143.221.15", "NL", "Haarlem", 52.387, 4.646, "WorldStream B.V."),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://pulse-surveys-online.biz/survey/start?id=corp"],
        "domain": "pulse-surveys-online.biz",
    },

    # --------------------------------------------------------------------------
    # C. PHISHING RECORDS (5 items, Scores 62.0 - 82.0, Tier: High 51-75 & Crit >75)
    # --------------------------------------------------------------------------
    {
        "id": "33333333-0001-4000-8000-000000000001",
        "sender": "Microsoft 365 Security <security@microsoft-auth-verify.com>",
        "recipients": ["sarah.jenkins@enterprise-corp.com"],
        "subject": "CRITICAL: Microsoft 365 Password Expires Within 2 Hours",
        "body_text": "Your Enterprise Corp corporate login password will expire today. To retain access without interruption, verify your credentials immediately at: https://microsoft-auth-verify.com/login",
        "days_ago": 2,
        "label": "PHISHING",
        "confidence": 0.94,
        "score": 78.5,
        "severity": "critical",
        "auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "relay_ips": [
            ("185.176.27.99", "RU", "Saint Petersburg", 59.934, 30.335, "Spamhaus Blocklist ASN"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["https://microsoft-auth-verify.com/login?target=enterprise-corp"],
        "domain": "microsoft-auth-verify.com",
    },
    {
        "id": "33333333-0002-4000-8000-000000000002",
        "sender": "Identity Protection Team <no-reply@sec-identity-login.com>",
        "recipients": ["advait@enterprise-corp.com"],
        "subject": "Security Alert: Unauthorized sign-in detected from unrecognized IP in Lagos",
        "body_text": "We detected an unfamiliar sign-in attempt on your SSO account from Lagos, Nigeria (IP: 105.112.98.14). If this was not you, lock your credentials immediately at: http://sec-identity-login.com/remediate",
        "days_ago": 2,
        "label": "PHISHING",
        "confidence": 0.91,
        "score": 82.0,
        "severity": "critical",
        "auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "relay_ips": [
            ("105.112.98.14", "NG", "Lagos", 6.524, 3.379, "Airtel Nigeria"),
            ("185.176.27.99", "RU", "Saint Petersburg", 59.934, 30.335, "MTA Bulletproof Relay"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://sec-identity-login.com/remediate?u=advait"],
        "domain": "sec-identity-login.com",
    },
    {
        "id": "33333333-0003-4000-8000-000000000003",
        "sender": "HR Portal Admin <support@workday-portal-secure.net>",
        "recipients": ["finance@enterprise-corp.com"],
        "subject": "Action Required: Update your Direct Deposit Account Details Before Payroll Cutoff",
        "body_text": "Recent banking regulations require all employees to re-authenticate their direct deposit routing number. Failure to update will delay this month's salary disbursement: http://workday-portal-secure.net/payroll",
        "days_ago": 1,
        "label": "PHISHING",
        "confidence": 0.88,
        "score": 74.0,
        "severity": "high",
        "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
        "relay_ips": [
            ("45.154.255.80", "NL", "Amsterdam", 52.367, 4.904, "Serverion B.V."),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://workday-portal-secure.net/payroll/verify"],
        "domain": "workday-portal-secure.net",
    },
    {
        "id": "33333333-0004-4000-8000-000000000004",
        "sender": "IT Infrastructure Support <admin@globalprotect-auth.org>",
        "recipients": ["devops@enterprise-corp.com"],
        "subject": "Urgent Notice: Corporate VPN Client Certificate Revocation Warning",
        "body_text": "Your GlobalProtect SSL VPN client certificate will be automatically revoked tonight at midnight due to CA rollover. Download the replacement profile: http://globalprotect-auth.org/renew-profile",
        "days_ago": 1,
        "label": "PHISHING",
        "confidence": 0.86,
        "score": 71.5,
        "severity": "high",
        "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
        "relay_ips": [
            ("193.106.191.22", "RU", "Moscow", 55.755, 37.617, "Selectel ASN"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://globalprotect-auth.org/renew-profile?client=paloalto"],
        "domain": "globalprotect-auth.org",
    },
    {
        "id": "33333333-0005-4000-8000-000000000005",
        "sender": "DocuSign Envelope Service <signatures@docusign-envelope-review.com>",
        "recipients": ["legal@enterprise-corp.com"],
        "subject": "DocuSign: Please sign 'Separation & Severance Agreement 2026'",
        "body_text": "Human Resources has sent you an encrypted document for signature. Click below to review and electronically sign: http://docusign-envelope-review.com/view/docusign/envelope/992410",
        "days_ago": 0,
        "label": "PHISHING",
        "confidence": 0.85,
        "score": 68.0,
        "severity": "high",
        "auth": {"spf": "softfail", "dkim": "none", "dmarc": "none"},
        "relay_ips": [
            ("185.220.101.9", "NL", "Amsterdam", 52.367, 4.904, "Tor Relay"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://docusign-envelope-review.com/view/docusign/envelope/992410"],
        "domain": "docusign-envelope-review.com",
    },

    # --------------------------------------------------------------------------
    # D. HIGH-RISK / BEC FRAUD RECORDS (4 items, Scores 88.0 - 96.0, Tier: Critical >75)
    # --------------------------------------------------------------------------
    {
        "id": "44444444-0001-4000-8000-000000000001",
        "sender": "Satya Nadella <satya.nadella@corp-executive-office.com>",
        "recipients": ["cfo@enterprise-corp.com"],
        "subject": "CONFIDENTIAL: Urgent Acquisition Wire Transfer of $480,000 USD",
        "body_text": "David,\n\nI am currently in an off-site board meeting regarding the Project Falcon acquisition. Due to strict SEC NDAs, this transaction must remain strictly between us. I need you to initiate an urgent wire transfer of $480,000 USD to escrow account #9941-8201. Please reply immediately once ready for wire details.\n\nSatya",
        "days_ago": 1,
        "label": "BEC_FRAUD",
        "confidence": 0.96,
        "score": 96.0,
        "severity": "critical",
        "auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "relay_ips": [
            ("194.26.29.115", "RU", "Saint Petersburg", 59.934, 30.335, "APT / Bulletproof MTA"),
            ("185.176.27.99", "RU", "Saint Petersburg", 59.934, 30.335, "Command Relay"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": [],
        "domain": "corp-executive-office.com",
    },
    {
        "id": "44444444-0002-4000-8000-000000000002",
        "sender": "Chief Executive Officer <ceo@executive-priority-mail.net>",
        "recipients": ["payroll@enterprise-corp.com"],
        "subject": "URGENT: Payroll Direct Deposit Change for Next Pay Cycle",
        "body_text": "Good morning,\n\nI have switched my personal banking institution from Chase to Metropolitan Commercial Bank. Please update my direct deposit routing and bank details for tomorrow's pay run. Do not notify my EA as I am traveling overseas.\n\nRouting: 026009593\nAccount: 94819201948",
        "days_ago": 1,
        "label": "BEC_FRAUD",
        "confidence": 0.94,
        "score": 92.5,
        "severity": "critical",
        "auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "relay_ips": [
            ("185.176.27.99", "RU", "Saint Petersburg", 59.934, 30.335, "MTA Bulletproof Relay"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": [],
        "domain": "executive-priority-mail.net",
    },
    {
        "id": "44444444-0003-4000-8000-000000000003",
        "sender": "Acme Global Supplier <invoicing@acme-supplier-holdings.com>",
        "recipients": ["accounts-payable@enterprise-corp.com"],
        "subject": "OVERDUE INVOICE: Updated Banking Information for PO #48201",
        "body_text": "Attention Accounts Payable:\n\nOur primary depository account is undergoing a financial reconciliation audit. For invoice #INV-48201 ($128,450.00), wire all funds to our new intermediary account immediately to prevent delivery shipment halts.\n\nSwift: BARCGB22\nIBAN: GB42BARC20201599482011",
        "days_ago": 0,
        "label": "BEC_FRAUD",
        "confidence": 0.91,
        "score": 94.0,
        "severity": "critical",
        "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
        "relay_ips": [
            ("194.26.29.115", "RU", "Saint Petersburg", 59.934, 30.335, "Bulletproof Ingress"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": ["http://acme-supplier-holdings.com/remit/INV48201"],
        "domain": "acme-supplier-holdings.com",
    },
    {
        "id": "44444444-0004-4000-8000-000000000004",
        "sender": "Executive Office <ceo-mobile-sms@executive-priority-mail.net>",
        "recipients": ["office-manager@enterprise-corp.com"],
        "subject": "Quick Favor: Urgent Apple Gift Card Purchase for Client Summit",
        "body_text": "Hi,\n\nAre you at your desk? I am tied up in an unscheduled executive board meeting and need a quick favor. Please purchase 10x $100 Apple iTunes gift cards from the store for our client gifts today. Scratch the codes and email photos to this address right away. I will reimburse on my corporate card.",
        "days_ago": 0,
        "label": "BEC_FRAUD",
        "confidence": 0.93,
        "score": 89.0,
        "severity": "critical",
        "auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        "relay_ips": [
            ("185.176.27.99", "RU", "Saint Petersburg", 59.934, 30.335, "MTA Bulletproof Relay"),
            ("198.51.100.12", "US", "New York", 40.712, -74.006, "Corporate Ingress"),
        ],
        "urls": [],
        "domain": "executive-priority-mail.net",
    },
]


async def seed_demo(confirm: bool = False):
    if not confirm:
        logger.error("Database reset not confirmed. Use --confirm to safely reset and seed demo data.")
        sys.exit(1)

    logger.info("=== 1. CONNECTING TO DATABASE ===")
    async with AsyncSessionLocal() as session:
        # 1. Clean existing records respecting foreign key constraints
        logger.info("Safely deleting existing demo records (preserving users & organizations)...")
        await session.execute(delete(AuditLog))
        await session.execute(delete(CaseNote))
        await session.execute(delete(CaseEmail))
        await session.execute(delete(Alert))
        await session.execute(delete(AnalysisResult))
        await session.execute(delete(Case))
        await session.execute(delete(Email))
        await session.commit()
        logger.info("Existing demo records cleared.")

        # 2. Ensure default organization & admin user exist
        org_res = await session.execute(select(Organization).where(Organization.slug == "default"))
        org = org_res.scalar_one_or_none()
        if not org:
            org = Organization(name="Enterprise Security SOC", slug="default", is_active=True)
            session.add(org)
            await session.flush()

        user_res = await session.execute(select(User).where(User.email == "admin@mailforensix.local"))
        admin_user = user_res.scalar_one_or_none()
        if not admin_user:
            admin_user = User(
                email="admin@mailforensix.local",
                hashed_password=get_password_hash("admin123"),
                role=UserRole.admin,
                org_id=org.id,
                is_active=True,
            )
            session.add(admin_user)
            await session.flush()
            logger.info("Admin user created: admin@mailforensix.local / admin123")
        else:
            logger.info("Admin user verified: admin@mailforensix.local")

        # 3. Seed 36 diverse emails & analysis results
        logger.info(f"=== 2. SEEDING {len(DEMO_RECORDS)} FORENSIC EMAIL RECORDS ===")
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        
        email_instances = []
        analysis_instances = []

        for item in DEMO_RECORDS:
            eid = UUID(item["id"])
            ingested_time = now - timedelta(days=item["days_ago"], hours=item.get("hours_ago", 2))

            # Build realistic RFC-822 MIME raw message
            raw_eml = (
                f"From: {item['sender']}\r\n"
                f"To: {', '.join(item['recipients'])}\r\n"
                f"Subject: {item['subject']}\r\n"
                f"Date: {ingested_time.strftime('%a, %d %b %Y %H:%M:%S +0000')}\r\n"
                f"Message-ID: <threat-{eid.hex[:8]}@mailforensix.internal>\r\n"
                f"MIME-Version: 1.0\r\n"
                f"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
                f"{item['body_text']}\r\n"
            ).encode("utf-8")

            hashes = compute_hashes(raw_eml)

            # Construct headers dict
            headers_dict = {
                "from": item["sender"],
                "to": ", ".join(item["recipients"]),
                "subject": item["subject"],
                "date": ingested_time.isoformat(),
                "message-id": f"<threat-{eid.hex[:8]}@mailforensix.internal>",
                "received_hops": [
                    {
                        "hop_index": idx,
                        "ip": ip,
                        "from_host": f"mta-{idx}.{item['domain']}",
                        "by_host": "relay.enterprise-corp.com",
                        "timestamp": (ingested_time - timedelta(minutes=idx * 2)).isoformat(),
                        "delay_seconds": idx * 12,
                    }
                    for idx, (ip, _, _, _, _, _) in enumerate(item["relay_ips"])
                ],
            }

            email_obj = Email(
                id=eid,
                raw_hash_sha256=hashes["sha256"],
                raw_hash_sha1=hashes["sha1"],
                raw_hash_md5=hashes["md5"],
                sender=item["sender"],
                recipients=item["recipients"],
                subject=item["subject"],
                body_text=item["body_text"],
                body_html=f"<div><p>{item['body_text']}</p></div>",
                headers=headers_dict,
                attachments=[],
                urls=item["urls"],
                raw_eml=raw_eml,
                ingested_at=ingested_time,
                status=EmailStatus.analyzed,
            )
            email_instances.append(email_obj)

            # Build MTA relay & Geo data for map
            relay_hops_list = [
                {
                    "hop_index": idx,
                    "from_host": f"mta-{idx}.{item['domain']}",
                    "by_host": "mail.enterprise-corp.com",
                    "ip": ip,
                    "timestamp": (ingested_time - timedelta(minutes=idx * 2)).isoformat(),
                    "delay_seconds": idx * 8,
                }
                for idx, (ip, _, _, _, _, _) in enumerate(item["relay_ips"])
            ]

            geo_data_list = [
                {
                    "hop_index": idx,
                    "ip": ip,
                    "country": country,
                    "city": city,
                    "latitude": lat,
                    "longitude": lon,
                    "isp": isp,
                }
                for idx, (ip, country, city, lat, lon, isp) in enumerate(item["relay_ips"])
            ]

            # Build Attribution Graph Subgraph for this email
            sender_domain = item["domain"]
            graph_nodes = [
                {"id": f"email_{eid}", "type": "email", "label": item["subject"][:25], "risk": item["score"]},
                {"id": f"domain_{sender_domain}", "type": "domain", "label": sender_domain, "risk": item["score"]},
            ]
            graph_edges = [
                {"source": f"email_{eid}", "target": f"domain_{sender_domain}", "relationship": "originates_from"}
            ]

            for ip, country, _, _, _, _ in item["relay_ips"]:
                graph_nodes.append({"id": f"ip_{ip}", "type": "ip", "label": f"{ip} ({country})", "risk": item["score"]})
                graph_edges.append({"source": f"email_{eid}", "target": f"ip_{ip}", "relationship": "routed_through"})

            for url in item["urls"]:
                url_id = hashlib.md5(url.encode()).hexdigest()[:8]
                graph_nodes.append({"id": f"url_{url_id}", "type": "url", "label": url[:30], "risk": item["score"]})
                graph_edges.append({"source": f"email_{eid}", "target": f"url_{url_id}", "relationship": "contains_link"})

            # Build IOC list
            iocs = []
            for ip, _, _, _, _, _ in item["relay_ips"]:
                iocs.append({"type": "ip", "value": ip, "threat": "mta_hop"})
            for url in item["urls"]:
                iocs.append({"type": "url", "value": url, "threat": "embedded_link"})
            iocs.append({"type": "domain", "value": sender_domain, "threat": "sender_domain"})

            # Build probability distribution based on canonical uppercase label
            probs = {"LEGITIMATE": 1.0, "SUSPICIOUS": 1.0, "PHISHING": 1.0, "BEC_FRAUD": 1.0, "IMPERSONATION": 1.0}
            target_label = item["label"]
            for k in probs:
                if k == target_label:
                    probs[k] = round(item["confidence"] * 100.0, 1)
                else:
                    rem = round(((1.0 - item["confidence"]) / 4.0) * 100.0, 1)
                    probs[k] = max(0.1, rem)

            # Build AnalysisResult record
            analysis_obj = AnalysisResult(
                id=uuid4(),
                email_id=eid,
                nlp_label=target_label,
                nlp_confidence=round(item["confidence"] * 100.0, 1),
                nlp_details={
                    "probabilities": probs,
                    "urgency_score": 75.0 if item["severity"] == "critical" else (35.0 if item["severity"] == "medium" else 5.0),
                    "bec_indicators": ["wire_transfer", "confidential"] if target_label == "BEC_FRAUD" else [],
                    "impersonation_signals": ["lookalike_domain", "executive_display_name"] if target_label in ("PHISHING", "BEC_FRAUD") else [],
                    "confidence_calibrated": True,
                    "confidence_method": "ensemble_stacking",
                    "evidence_score": round(item["confidence"] * 100.0, 1),
                },
                auth_status={
                    "spf": item["auth"]["spf"],
                    "spf_status": item["auth"]["spf"],
                    "dkim": item["auth"]["dkim"],
                    "dkim_status": item["auth"]["dkim"],
                    "dmarc": item["auth"]["dmarc"],
                    "dmarc_status": item["auth"]["dmarc"],
                },
                relay_path=relay_hops_list,
                geo_data=geo_data_list,
                ip_reputation={"score": 85.0 if item["severity"] in ("high", "critical") else 10.0},
                domain_intel={
                    "domain": sender_domain,
                    "age_days": 14 if item["severity"] in ("high", "critical") else 1850,
                    "is_typosquat": item["severity"] in ("high", "critical"),
                    "asn": "AS20492" if "RU" in [c for _, c, _, _, _, _ in item["relay_ips"]] else "AS16509",
                    "registrar": "NameCheap / Bulletproof" if item["severity"] in ("high", "critical") else "MarkMonitor Inc.",
                },
                iocs=iocs,
                composite_risk_score=item["score"],
                risk_breakdown={
                    "severity": item["severity"],
                    "recommended_action": (
                        "Immediate incident containment and credential revocation"
                        if item["severity"] == "critical"
                        else ("SOC analyst triage and sandbox detonation" if item["severity"] == "high" else "No remediation required")
                    ),
                    "nlp": round(item["score"] * 0.35, 1),
                    "auth": round(item["score"] * 0.25, 1),
                    "ip": round(item["score"] * 0.20, 1),
                    "link": round(item["score"] * 0.10, 1),
                    "attachment": round(item["score"] * 0.10, 1),
                    "factors": [
                        {"name": "NLP Semantic Threat Classification", "raw_score": item["score"], "weight": 0.35},
                        {"name": "MTA Authentication Alignment (SPF/DKIM)", "raw_score": 85.0 if item["auth"]["spf"] == "fail" else 5.0, "weight": 0.25},
                        {"name": "Sender IP Infrastructure Reputation", "raw_score": 80.0 if item["severity"] in ("high", "critical") else 10.0, "weight": 0.20},
                    ],
                },
                attribution_category=(
                    "FIN7 Targeted Executive BEC" if target_label == "BEC_FRAUD"
                    else ("Credential Harvesting Campaign" if target_label == "PHISHING" else "Routine Corporate Communication")
                ),
                attribution_confidence=round(item["confidence"] * 100.0, 1),
                graph_data={"nodes": graph_nodes, "edges": graph_edges},
                analyzed_at=ingested_time + timedelta(seconds=15),
            )
            analysis_instances.append(analysis_obj)

        session.add_all(email_instances)
        await session.commit()
        logger.info(f"{len(email_instances)} email records committed.")

        session.add_all(analysis_instances)
        await session.commit()
        logger.info(f"{len(analysis_instances)} analysis results committed.")

        # 4. Seed 3 Active Investigation Cases
        logger.info("=== 3. SEEDING 3 ACTIVE SOC INVESTIGATION CASES ===")
        case1_id = uuid4()
        case1 = Case(
            id=case1_id,
            title="Investigation: FIN7 Executive Impersonation & Wire Fraud Campaign",
            description="Coordinated Business Email Compromise campaign targeting finance leadership. Uses Russian bulletproof infrastructure (AS20492) and spoofed executive display names.",
            status=CaseStatus.investigating,
            severity=CaseSeverity.critical,
            assigned_to="admin@mailforensix.local",
            created_at=now - timedelta(days=1),
            updated_at=now,
        )
        session.add(case1)

        case2_id = uuid4()
        case2 = Case(
            id=case2_id,
            title="Credential Harvesting: Microsoft 365 & SSO Lookalike Domains",
            description="Multi-vector phishing operation deploying lookalike domains (microsoft-auth-verify.com, sec-identity-login.com). Originates from bulletproof relay in St. Petersburg and Lagos IP pool.",
            status=CaseStatus.open,
            severity=CaseSeverity.high,
            assigned_to="admin@mailforensix.local",
            created_at=now - timedelta(days=2),
            updated_at=now,
        )
        session.add(case2)

        case3_id = uuid4()
        case3 = Case(
            id=case3_id,
            title="Vendor Supply Chain Infiltration & Account Takeover (Acme Global)",
            description="Suspicious remittance update request attempting to hijack invoice #INV-48201 payments to fraudulent offshore accounts.",
            status=CaseStatus.investigating,
            severity=CaseSeverity.high,
            assigned_to="admin@mailforensix.local",
            created_at=now - timedelta(hours=14),
            updated_at=now,
        )
        session.add(case3)
        await session.flush()

        # Link emails to cases
        # Case 1: Wire fraud & Gift card emails
        session.add(CaseEmail(case_id=case1_id, email_id=UUID("44444444-0001-4000-8000-000000000001")))
        session.add(CaseEmail(case_id=case1_id, email_id=UUID("44444444-0002-4000-8000-000000000002")))
        session.add(CaseEmail(case_id=case1_id, email_id=UUID("44444444-0004-4000-8000-000000000004")))

        # Case 2: M365 and SSO credential phish
        session.add(CaseEmail(case_id=case2_id, email_id=UUID("33333333-0001-4000-8000-000000000001")))
        session.add(CaseEmail(case_id=case2_id, email_id=UUID("33333333-0002-4000-8000-000000000002")))

        # Case 3: Vendor PO invoice
        session.add(CaseEmail(case_id=case3_id, email_id=UUID("44444444-0003-4000-8000-000000000003")))

        # Add Case Notes
        session.add(CaseNote(
            case_id=case1_id,
            author="admin@mailforensix.local",
            content="Triaged MTA hops: Origin IP 194.26.29.115 traces to known threat actor cluster. Blocked domain corp-executive-office.com at perimeter gateway.",
            created_at=now - timedelta(hours=18),
        ))
        session.add(CaseNote(
            case_id=case1_id,
            author="admin@mailforensix.local",
            content="Notified CFO David regarding fraudulent wire request. Verified zero financial funds were transmitted.",
            created_at=now - timedelta(hours=6),
        ))
        session.add(CaseNote(
            case_id=case2_id,
            author="admin@mailforensix.local",
            content="Submitted takedown abuse tickets to NameCheap registrar for microsoft-auth-verify.com. Added URL regex rules to security proxy.",
            created_at=now - timedelta(hours=12),
        ))
        await session.commit()
        logger.info("3 SOC Cases and case notes created.")

        # 5. Seed 4 Unacknowledged Alerts (Triage Queue) + 2 Acknowledged Alerts
        logger.info("=== 4. SEEDING TRIAGE QUEUE ALERTS ===")
        alerts = [
            Alert(
                id=uuid4(),
                email_id=UUID("44444444-0001-4000-8000-000000000001"),
                severity=AlertSeverity.critical,
                message="Critical BEC: Executive Wire Fraud Campaign Detected ($480,000 USD transfer)",
                risk_score=96.0,
                contributing_factors={"nlp_label": "BEC_FRAUD", "urgency": "critical", "spf": "fail"},
                acknowledged=False,
                created_at=now - timedelta(hours=18),
            ),
            Alert(
                id=uuid4(),
                email_id=UUID("44444444-0002-4000-8000-000000000002"),
                severity=AlertSeverity.critical,
                message="Critical BEC: CEO Payroll Routing Redirection Attempt",
                risk_score=92.5,
                contributing_factors={"nlp_label": "BEC_FRAUD", "impersonation": True, "spf": "fail"},
                acknowledged=False,
                created_at=now - timedelta(hours=14),
            ),
            Alert(
                id=uuid4(),
                email_id=UUID("33333333-0001-4000-8000-000000000001"),
                severity=AlertSeverity.critical,
                message="Critical Phishing: Microsoft 365 Credential Harvesting with Lookalike Domain",
                risk_score=78.5,
                contributing_factors={"nlp_label": "PHISHING", "typosquat": True, "spf": "fail"},
                acknowledged=False,
                created_at=now - timedelta(hours=8),
            ),
            Alert(
                id=uuid4(),
                email_id=UUID("44444444-0003-4000-8000-000000000003"),
                severity=AlertSeverity.high,
                message="High-Risk BEC: Vendor Invoice Banking Details Alteration Notice",
                risk_score=94.0,
                contributing_factors={"nlp_label": "BEC_FRAUD", "vendor_mismatch": True},
                acknowledged=False,
                created_at=now - timedelta(hours=4),
            ),
            # Acknowledged alerts (historical triage)
            Alert(
                id=uuid4(),
                email_id=UUID("33333333-0002-4000-8000-000000000002"),
                severity=AlertSeverity.critical,
                message="Historical Alert: SSO Anomaly from Lagos IP Address",
                risk_score=82.0,
                contributing_factors={"geo_anomaly": True},
                acknowledged=True,
                created_at=now - timedelta(days=2),
            ),
            Alert(
                id=uuid4(),
                email_id=UUID("33333333-0004-4000-8000-000000000004"),
                severity=AlertSeverity.high,
                message="Historical Alert: Fake VPN Certificate Revocation Lure",
                risk_score=71.5,
                contributing_factors={"credential_phish": True},
                acknowledged=True,
                created_at=now - timedelta(days=1),
            ),
        ]
        session.add_all(alerts)
        await session.commit()
        logger.info(f"{len(alerts)} Alerts persisted (4 unacknowledged in triage queue).")

        # 6. Verify Dashboard Metrics Consistency
        logger.info("=== 5. MATHEMATICAL RECONCILIATION AUDIT ===")
        total_e = (await session.execute(select(Email))).scalars().all()
        total_a = (await session.execute(select(AnalysisResult))).scalars().all()
        unack_a = (await session.execute(select(Alert).where(Alert.acknowledged.is_(False)))).scalars().all()
        active_c = (await session.execute(select(Case).where(Case.status.in_([CaseStatus.open, CaseStatus.investigating])))).scalars().all()
        threats_flagged = [a for a in total_a if a.composite_risk_score > 50.0]
        clean_emails = [a for a in total_a if a.composite_risk_score <= 50.0]

        # Category breakdown
        cat_counts = {}
        for a in total_a:
            cat_counts[a.nlp_label] = cat_counts.get(a.nlp_label, 0) + 1

        # Risk tier breakdown
        tier_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for a in total_a:
            s = a.composite_risk_score
            if s <= 25.0:
                tier_counts["low"] += 1
            elif s <= 50.0:
                tier_counts["medium"] += 1
            elif s <= 75.0:
                tier_counts["high"] += 1
            else:
                tier_counts["critical"] += 1

        logger.info(f"Total Envelopes: {len(total_e)}")
        logger.info(f"Total Analyzed: {len(total_a)}")
        logger.info(f"Clean Envelopes (Score <= 50): {len(clean_emails)}")
        logger.info(f"Threats Flagged (Score > 50): {len(threats_flagged)}")
        logger.info(f"Active SOC Cases: {len(active_c)}")
        logger.info(f"Unack Triage Alerts: {len(unack_a)}")
        logger.info(f"NLP Threat Categories: {json.dumps(cat_counts, indent=2)}")
        logger.info(f"Risk Tiers: {json.dumps(tier_counts, indent=2)}")

        # Verification asserts
        assert len(total_e) == len(total_a) == 36, "Total emails and analyses must equal 36"
        assert len(clean_emails) + len(threats_flagged) == 36, "Clean + Flagged must equal 36"
        assert sum(cat_counts.values()) == 36, "Categories must sum to 36"
        assert sum(tier_counts.values()) == 36, "Risk tiers must sum to 36"
        assert "Legitimate" not in cat_counts, "Duplicate title-case Legitimate must not exist!"
        assert cat_counts.get("LEGITIMATE", 0) == 20, "LEGITIMATE must be exactly 20"
        assert cat_counts.get("SUSPICIOUS", 0) == 7, "SUSPICIOUS must be exactly 7"
        assert cat_counts.get("PHISHING", 0) == 5, "PHISHING must be exactly 5"
        assert cat_counts.get("BEC_FRAUD", 0) == 4, "BEC_FRAUD must be exactly 4"
        assert len(active_c) == 3, "Active cases must be 3"
        assert len(unack_a) == 4, "Unacknowledged alerts must be 4"

        logger.info(">>> MATHEMATICAL RECONCILIATION AUDIT PASSED 100%! <<<")
        logger.info("Demo seeding is complete and the application is ready for demonstration.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MailForensix Hackathon Demo Data Seeding Script")
    parser.add_argument("--confirm", action="store_true", help="Confirm database reset and seeding")
    args = parser.parse_args()

    asyncio.run(seed_demo(confirm=args.confirm))

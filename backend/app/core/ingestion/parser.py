import email
from email import policy
import eml_parser
from bs4 import BeautifulSoup
import tldextract
import hashlib
import re
from email.utils import parsedate_to_datetime
import chardet
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class ParsedEmail:
    sender: str
    recipients: List[str]
    subject: str
    body_text: str
    body_html: str
    headers: Dict[str, Any]
    received_hops: List[Dict[str, Any]]
    attachments: List[Dict[str, Any]]
    urls: List[str]
    message_id: str
    reply_to: str
    return_path: str
    x_originating_ip: str

class EmailParser:
    def parse(self, raw_bytes: bytes) -> ParsedEmail:
        if raw_bytes.startswith(b'\xef\xbb\xbf'):
            raw_bytes = raw_bytes[3:]

        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        
        sender = msg.get("From", "")
        recipients = []
        for header in ["To", "Cc", "Bcc"]:
            val = msg.get_all(header, [])
            for v in val:
                recipients.extend([r.strip() for r in v.split(",")])
        
        subject = msg.get("Subject", "")
        body_text = ""
        body_html = ""
        attachments = []
        
        for part in msg.walk():
            content_type = part.get_content_type()
            if part.get_content_maintype() == 'multipart':
                continue
                
            filename = part.get_filename()
            if not filename:
                content = part.get_payload(decode=True)
                if not content:
                    continue
                try:
                    charset = part.get_content_charset() or chardet.detect(content)['encoding'] or 'utf-8'
                    decoded = content.decode(charset, errors='replace')
                    if content_type == 'text/plain':
                        body_text += decoded
                    elif content_type == 'text/html':
                        body_html += decoded
                except Exception:
                    pass
            else:
                content = part.get_payload(decode=True)
                if content:
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "content": content
                    })

        urls = []
        if body_html:
            soup = BeautifulSoup(body_html, "html.parser")
            for tag in soup.find_all(['a', 'img', 'form']):
                href = tag.get('href') or tag.get('src') or tag.get('action')
                if href and href.startswith('http'):
                    urls.append(href)
                    
        if body_text:
            text_urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', body_text)
            urls.extend(text_urls)
            
        urls = list(set(urls))
        
        received_hops = []
        received_headers = msg.get_all("Received", [])
        
        for idx, header in enumerate(received_headers):
            hop = {"hop_number": len(received_headers) - idx}
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
            if ips:
                hop["ip"] = ips[0]
            else:
                hop["ip"] = ""
                
            date_match = re.search(r';\s*(.+)$', header)
            if date_match:
                try:
                    dt = parsedate_to_datetime(date_match.group(1))
                    hop["timestamp"] = dt.isoformat()
                except:
                    pass
                    
            received_hops.append(hop)
            
        received_hops.reverse()
        
        headers_dict = dict(msg.items())
        headers_dict["received_hops"] = received_hops
        
        return ParsedEmail(
            sender=sender,
            recipients=recipients,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            headers=headers_dict,
            received_hops=received_hops,
            attachments=attachments,
            urls=urls,
            message_id=msg.get("Message-ID", ""),
            reply_to=msg.get("Reply-To", ""),
            return_path=msg.get("Return-Path", ""),
            x_originating_ip=msg.get("X-Originating-IP", "")
        )

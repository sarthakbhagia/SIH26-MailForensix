import unicodedata
import urllib.parse
from bs4 import BeautifulSoup
import hashlib
from app.core.ingestion.parser import ParsedEmail

class EmailPreprocessor:
    def preprocess(self, parsed: ParsedEmail) -> ParsedEmail:
        parsed.sender = unicodedata.normalize('NFKC', parsed.sender)
        parsed.subject = unicodedata.normalize('NFKC', parsed.subject)
        parsed.body_text = unicodedata.normalize('NFKC', parsed.body_text)
        
        parsed.urls = [urllib.parse.unquote(url) for url in parsed.urls]
        
        clean_urls = []
        for url in parsed.urls:
            try:
                parsed_url = urllib.parse.urlparse(url)
                netloc = parsed_url.netloc.encode('idna').decode('utf-8')
                clean_urls.append(urllib.parse.urlunparse(parsed_url._replace(netloc=netloc)))
            except Exception:
                clean_urls.append(url)
        parsed.urls = clean_urls
        
        if parsed.body_html:
            soup = BeautifulSoup(parsed.body_html, "html.parser")
            for script in soup(['script', 'style']):
                script.extract()
            parsed.body_html = str(soup)
            
        canonical_str = f"{parsed.sender}|{','.join(sorted(parsed.recipients))}|{parsed.subject}|{parsed.body_text}"
        parsed.canonical_hash = hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()
        
        return parsed

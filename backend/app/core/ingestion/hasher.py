import hashlib
from dataclasses import dataclass

@dataclass
class HashResult:
    sha256: str
    sha1: str
    md5: str

class EvidenceHasher:
    def hash(self, raw_bytes: bytes) -> HashResult:
        return HashResult(
            sha256=hashlib.sha256(raw_bytes).hexdigest(),
            sha1=hashlib.sha1(raw_bytes).hexdigest(),
            md5=hashlib.md5(raw_bytes).hexdigest()
        )
        
    def hash_attachment(self, content: bytes) -> HashResult:
        return self.hash(content)

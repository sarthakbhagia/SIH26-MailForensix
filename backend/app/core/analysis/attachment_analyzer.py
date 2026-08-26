import re
import zipfile
import io
import magic

from dataclasses import dataclass, asdict
from typing import List, Optional

HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".msi", ".dll", ".com", ".pif", ".hta",
}


@dataclass
class AttachmentAnalysisResult:
    filename: str
    declared_content_type: str
    actual_content_type: str
    size_bytes: int
    sha256: str
    risk_score: float
    risk_reasons: List[str]
    has_macros: bool
    extension_mismatch: bool
    is_double_extension: bool
    vt_detections: int | None


@dataclass
class AttachmentAnalysisReport:
    total_attachments: int
    results: List[AttachmentAnalysisResult]
    overall_attachment_risk: float


class AttachmentAnalyzer:
    def analyze(self, attachments: list[dict]) -> AttachmentAnalysisReport:
        if not attachments:
            return AttachmentAnalysisReport(
                total_attachments=0,
                results=[],
                overall_attachment_risk=0.0,
            )

        results: list[AttachmentAnalysisResult] = []
        total_risk = 0.0

        for att in attachments:
            content = att.get("content", b"")
            filename = att.get("filename", "unknown")
            declared_type = att.get("declared_content_type", "")

            actual_type = magic.from_buffer(content, mime=True)
            size = len(content)

            # SHA256
            import hashlib
            sha256 = hashlib.sha256(content).hexdigest()

            # Extension checks
            ext = re.search(r"\.(\w+)$", filename)
            ext_lower = ext.group(1).lower() if ext else ""
            is_double_ext = bool(re.search(r"\.\w+\.\w+$", filename))

            is_high_risk_ext = ext_lower in HIGH_RISK_EXTENSIONS if ext else False

            # Extension mismatch
            mismatch = declared_type and actual_type and declared_type != actual_type

            # Macro detection
            has_macros = self._has_macros(content, filename)

            # Risk scoring
            risk_score = 0.0
            risk_reasons: list[str] = []

            if is_high_risk_ext:
                risk_score += 80
                risk_reasons.append("executable_extension")

            if is_double_ext:
                risk_score += 60
                risk_reasons.append("double_extension")

            if mismatch:
                risk_score += 40
                risk_reasons.append("extension_mismatch")

            if has_macros:
                risk_score += 50
                risk_reasons.append("contains_macros")

            # Archive check
            if self._is_archive(filename):
                risk_score += 45

            # Size checks
            if size > 25 * 1024 * 1024:
                risk_score += 10
                risk_reasons.append("large_file")

            if size > 0 and size < 1024 and ext_lower in {"pdf", "doc", "xls"}:
                risk_score += 15
                risk_reasons.append("small_file")

            risk_score = min(100.0, risk_score)

            result = AttachmentAnalysisResult(
                filename=filename,
                declared_content_type=declared_type,
                actual_content_type=actual_type,
                size_bytes=size,
                sha256=sha256,
                risk_score=round(risk_score, 1),
                risk_reasons=risk_reasons,
                has_macros=has_macros,
                extension_mismatch=mismatch,
                is_double_extension=is_double_ext,
                vt_detections=None,
            )
            results.append(result)
            total_risk += risk_score

        overall_risk = round(total_risk / len(results), 1) if results else 0.0

        return AttachmentAnalysisReport(
            total_attachments=len(results),
            results=results,
            overall_attachment_risk=overall_risk,
        )

    @staticmethod
    def _has_macros(content: bytes, filename: str) -> bool:
        lowername = filename.lower()
        # Check for VBA project in ZIP (Office Open XML)
        if lowername.endswith((".docx", ".xlsx", ".pptx")):
            try:
                z = zipfile.ZipFile(io.BytesIO(content))
                return "vbaProject.bin" in z.namelist()
            except Exception:
                return False

        # Check for VBA bytes in OLE files
        if re.search(rb"VBA|Attribute VB_Name", content):
            return True

        return False

    @staticmethod
    def _is_archive(filename: str) -> bool:
        archive_ext = {".zip", ".rar", ".7z", ".tar", ".gz", ".pdf", ".doc", ".xls", ".ppt"}
        ext = re.search(r"\.(\w+)$", filename)
        if ext and ext.group(1).lower() in {a.lstrip(".") for a in archive_ext}:
            return True
        return False
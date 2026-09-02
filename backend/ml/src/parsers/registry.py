"""Parser Registry and Unified Dispatcher for MailForensix ML Pipeline."""

from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

from ml.src.parsers.base_parser import BaseDatasetParser
from ml.src.parsers.maildir_parser import MaildirParser
from ml.src.parsers.mbox_parser import MboxParser
from ml.src.parsers.rfc822_parser import RFC822Parser
from ml.src.parsers.csv_parser import CSVTabularParser
from ml.src.parsers.clair_parser import CLAIRParser
from ml.src.parsers.bec2_parser import BEC2Parser
from ml.src.schemas.canonical_email import CanonicalEmail


PARSER_CLASSES = {
    "maildir": MaildirParser,
    "mbox": MboxParser,
    "rfc822": RFC822Parser,
    "eml": RFC822Parser,
    "csv": CSVTabularParser,
    "tabular": CSVTabularParser,
    "tsv_csv_eml": CSVTabularParser,
    "json_csv": BEC2Parser,
    "clair": CLAIRParser,
    "clair_text": CLAIRParser,
    "bec2": BEC2Parser,
    "bec2_parser": BEC2Parser,
}


def get_parser(parser_name: str) -> BaseDatasetParser:
    """Instantiate and return the parser corresponding to parser_name."""
    name_clean = parser_name.lower().strip()
    parser_cls = PARSER_CLASSES.get(name_clean, RFC822Parser)
    return parser_cls()


def resolve_dataset_path(dataset_key: str, data_dir: Path, raw_subdir: str) -> Tuple[Path, str]:
    """Resolve actual on-disk dataset path and appropriate parser format."""
    target_path = data_dir / raw_subdir

    # 1. Check direct file or directory
    if target_path.exists():
        if target_path.is_file() and target_path.suffix.lower() == ".csv":
            return target_path, "csv"
        # Check special subpaths
        if dataset_key == "enron":
            for cand in [target_path / "enron_mail_20150507" / "maildir", target_path / "maildir", target_path]:
                if cand.exists() and any(cand.iterdir()):
                    return cand, "maildir"
        elif dataset_key == "epvme":
            extracted = target_path / "extracted"
            if extracted.exists() and any(extracted.iterdir()):
                return extracted, "rfc822"
        elif dataset_key == "phishing_pot":
            email_cand = target_path / "email"
            if email_cand.exists():
                return email_cand, "rfc822"
        elif dataset_key == "clair":
            csv_cand = target_path / "clair_email_fraud.csv"
            if csv_cand.exists():
                return csv_cand, "csv"
        elif dataset_key == "bec2":
            csv_cand = target_path / "data" / "BEC-2-human.csv"
            if csv_cand.exists():
                return csv_cand, "bec2"
        return target_path, ""

    # 2. Check alternative naming conventions in data_dir
    alt_candidates = [
        (data_dir / f"{dataset_key.upper()}.csv", "csv"),
        (data_dir / f"{dataset_key.lower()}.csv", "csv"),
        (data_dir / f"{dataset_key}.csv", "csv"),
    ]
    if dataset_key == "trec07":
        alt_candidates.insert(0, (data_dir / "TREC-07.csv", "csv"))
    elif dataset_key == "ceas08":
        alt_candidates.insert(0, (data_dir / "CEAS-08.csv", "csv"))

    for cand_path, fmt in alt_candidates:
        if cand_path.exists():
            return cand_path, fmt

    return target_path, ""


def parse_dataset_from_config(
    dataset_key: str,
    dataset_config: Dict[str, Any],
    data_dir: Path,
) -> Tuple[Iterator[CanonicalEmail], BaseDatasetParser]:
    """Dispatch dataset parsing using its configuration specification."""
    raw_subdir = dataset_config.get("raw_subdir", dataset_key)
    resolved_path, detected_fmt = resolve_dataset_path(dataset_key, data_dir, raw_subdir)

    parser_type = detected_fmt or dataset_config.get("parser") or dataset_config.get("format", "rfc822")
    parser = get_parser(parser_type)

    cfg = dict(dataset_config)
    cfg["dataset_key"] = dataset_key

    return parser.parse(resolved_path, cfg), parser

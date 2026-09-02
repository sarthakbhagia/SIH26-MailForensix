"""Dataset Parsers Package."""
from ml.src.parsers.base_parser import BaseDatasetParser, ParserStats
from ml.src.parsers.maildir_parser import MaildirParser
from ml.src.parsers.mbox_parser import MboxParser
from ml.src.parsers.rfc822_parser import RFC822Parser
from ml.src.parsers.csv_parser import CSVTabularParser
from ml.src.parsers.clair_parser import CLAIRParser
from ml.src.parsers.bec2_parser import BEC2Parser
from ml.src.parsers.registry import get_parser, parse_dataset_from_config

__all__ = [
    "BaseDatasetParser",
    "ParserStats",
    "MaildirParser",
    "MboxParser",
    "RFC822Parser",
    "CSVTabularParser",
    "CLAIRParser",
    "BEC2Parser",
    "get_parser",
    "parse_dataset_from_config",
]

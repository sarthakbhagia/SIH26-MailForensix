"""Base Dataset Parser Interface for MailForensix ML Pipeline.

Defines the common iterable interface:
`parse(dataset_path: Path, config: Dict[str, Any]) -> Iterator[CanonicalEmail]`
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ml.src.schemas.canonical_email import CanonicalEmail


@dataclass
class ParserStats:
    discovered_count: int = 0
    parseable_count: int = 0
    failed_count: int = 0
    parse_errors: List[Dict[str, Any]] = field(default_factory=list)


class BaseDatasetParser(ABC):
    """Abstract base class for dataset-specific email parsers."""

    def __init__(self):
        self.stats = ParserStats()

    def reset_stats(self):
        self.stats = ParserStats()

    @abstractmethod
    def parse(self, dataset_path: Path, config: Dict[str, Any]) -> Iterator[CanonicalEmail]:
        """Stream CanonicalEmail records from the dataset directory or file."""
        pass

from .base import Detector
from .credential_stuffing import CredentialStuffingDetector
from .distributed_cs import DistributedCSDetector
from .sql_injection import SqlInjectionDetector
from .data_exfiltration import DataExfiltrationDetector
from .anonymizer import AnonymizerDetector
from .admin_recon import AdminReconDetector
from .fingerprint import FingerprintDetector

ALL_DETECTORS = [
    CredentialStuffingDetector(),
    DistributedCSDetector(),
    SqlInjectionDetector(),
    DataExfiltrationDetector(),
    AnonymizerDetector(),
    AdminReconDetector(),
    FingerprintDetector(),
]

__all__ = [
    "Detector", "ALL_DETECTORS",
    "CredentialStuffingDetector", "DistributedCSDetector",
    "SqlInjectionDetector", "DataExfiltrationDetector",
    "AnonymizerDetector", "AdminReconDetector", "FingerprintDetector",
]

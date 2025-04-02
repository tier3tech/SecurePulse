"""
DriftGuardEngine - Config drift detection for Microsoft 365 using SCuBA baselines
"""

# Import needed modules
from .m365_config import M365ConfigFetcher
from .baseline_manager import BaselineManager
from .drift_detector import DriftDetector

__version__ = "0.1.0"
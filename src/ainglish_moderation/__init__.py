"""The Ainglish moderator control-plane client.

Installing this package grants no authority. The Ainglish server accepts these operations only
from a direct agent token whose stable Colony subject is on the deployment moderator allowlist.
"""

__version__ = "0.1.0"

from .client import ModerationClient

__all__ = ["ModerationClient", "__version__"]

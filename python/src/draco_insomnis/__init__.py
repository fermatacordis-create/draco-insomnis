"""Draco Insomnis for Python: the same firewall, block list, country filter, anti-copy pace, review
requests and CrowdSec bridge as the PHP and JavaScript editions, checked against the same shared test
cases. No dependencies. Adapters: draco_insomnis.asgi (FastAPI, Starlette…) and draco_insomnis.wsgi
(Flask, Django…)."""
from .crowdsec import CrowdSec, crowdsec_line
from .gatekeeper import SENSITIVE, TEXTS, Answer, Gatekeeper, page
from .geo import GeoFile
from .request import DracoRequest, client_ip
from .review import ReviewRequest, open_sealed, seal, sign
from .store import Blocks, DracoEvent, MemoryStore, Store, valid_net
from .waf import flatten, inspect

__version__ = "0.1.29"

__all__ = [
    "Answer", "Blocks", "CrowdSec", "DracoEvent", "DracoRequest", "Gatekeeper", "GeoFile", "MemoryStore",
    "ReviewRequest", "SENSITIVE", "Store", "TEXTS", "client_ip", "crowdsec_line", "flatten", "inspect",
    "open_sealed", "page", "seal", "sign", "valid_net", "__version__",
]

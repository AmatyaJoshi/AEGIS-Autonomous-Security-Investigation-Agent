"""Public dataset loaders (SPEC §5.3).

Each loader exposes ``download()`` (idempotent, cached under ``data/raw/<dataset>``),
``iter_events()`` yielding ``EcsEvent`` and ``ground_truth()`` yielding
``GroundTruthWindow`` rows derived from the dataset's *published* labels - never invented.
"""

from __future__ import annotations

from lab.datasets.bots import BotsLoader
from lab.datasets.cicids import CicIdsLoader
from lab.datasets.evtx_attack import EvtxAttackLoader
from lab.datasets.otrf import OtrfLoader

LOADERS = {
    "otrf": OtrfLoader,
    "evtx_attack": EvtxAttackLoader,
    "bots": BotsLoader,
    "cicids": CicIdsLoader,
}

__all__ = ["LOADERS", "BotsLoader", "CicIdsLoader", "EvtxAttackLoader", "OtrfLoader"]

"""sf-verify — re-derive a deployment's recorded admission decisions, offline.

Trusts nothing but its inputs: it re-computes the hash chain and checks it against a Signed Tree
Head. It proves the records are internally consistent and untampered. It CANNOT prove a deployment
recorded everything it should have — absence of a leak is a claim about events that were never
logged, and no log verifier can establish it.
"""
from ._anchor import verify_log_against_sth, verify_sth, verify_sth_chain  # noqa: F401
from ._decision_log import verify_log  # noqa: F401
from .verify import VerifyResult, verify_chain_file  # noqa: F401

__version__ = "0.1.0"
__license_tag__ = "CLEAN"

"""Feature-contract helpers for CICFlowMeter/CICDDoS2019 columns.

The trained model should only receive columns recorded in its artifact. This module
normalizes common CICFlowMeter spellings without pretending that arbitrary packets
are equivalent to CICFlowMeter flows.
"""
ALIASES = {
    "flow packets/s": "Flow Packets/s", "flow bytes/s": "Flow Bytes/s",
    "destination port": "Destination Port", "dst port": "Destination Port",
    "src port": "Source Port", "source port": "Source Port",
    "flow duration": "Flow Duration", "fwd packet length mean": "Fwd Packet Length Mean",
}

def normalize(features: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for key, value in features.items():
        canonical = ALIASES.get(str(key).strip().lower(), str(key).strip())
        try: out[canonical] = float(value)
        except (TypeError, ValueError): continue
    return out

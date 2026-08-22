"""
src/unified_schema.py - 3-Tier Multi-Source Event Schema & Normalization Engine
"""

import math
import numpy as np
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional

@dataclass
class UnifiedEvent:
    event_id: str
    timestamp: float  # Unix epoch seconds
    tier: str         # 'Tier1_Firewall', 'Tier2_WebWAF', 'Tier3_Endpoint'
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str     # 'TCP', 'UDP', 'HTTP', 'HTTPS', 'PROCESS'
    raw_payload: str  # URL, query string, or process commandline
    predicted_attack_type: str
    attack_confidence: float
    kill_chain_stage: int  # 0: Benign, 1: Recon, 2: Delivery/Exploit, 3: PrivEsc, 4: Exfil/C2
    campaign_id: Optional[str] = None
    is_attack: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def ip_to_int(ip_str: str) -> int:
    """Converts IPv4 string to 32-bit integer."""
    try:
        parts = [int(p) for p in ip_str.split('.')]
        if len(parts) == 4:
            return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    except Exception:
        pass
    return 0


def compute_ip_topology_distance(ip1: str, ip2: str) -> float:
    """
    Measures network distance between two IP addresses.
    Returns 0.0 (identical IP), 0.33 (/24 subnet match), 0.66 (/16 subnet match), 1.0 (distinct).
    """
    if ip1 == ip2:
        return 0.0
    p1 = ip1.split('.')
    p2 = ip2.split('.')
    if len(p1) == 4 and len(p2) == 4:
        if p1[:3] == p2[:3]:
            return 0.33
        if p1[:2] == p2[:2]:
            return 0.66
    return 1.0


def extract_pairwise_state_vector(e1: UnifiedEvent, e2: UnifiedEvent, max_window: float = 3600.0) -> np.ndarray:
    """
    Constructs a normalized 10-dimensional state vector representing the relationship
    between an active candidate anchor event (e1) and an incoming alert (e2).
    """
    # 1. Normalized Temporal Delta (0.0 to 1.0)
    delta_t = abs(e2.timestamp - e1.timestamp)
    delta_t_norm = min(1.0, delta_t / max_window)

    # 2. IP Distance
    ip_dist_src = compute_ip_topology_distance(e1.src_ip, e2.src_ip)
    ip_dist_dst = compute_ip_topology_distance(e1.dst_ip, e2.dst_ip)
    ip_match = 1.0 if (e1.dst_ip == e2.dst_ip or e1.src_ip == e2.src_ip or e1.dst_ip == e2.src_ip) else 0.0

    # 3. Port & Service Risk Alignment
    critical_ports = {80, 443, 8080, 22, 3389, 445, 1433, 3306}
    port_risk = 1.0 if (e2.dst_port in critical_ports or e1.dst_port in critical_ports) else 0.2

    # 4. Multi-Tier Transition (e.g. Tier 1 -> Tier 2 -> Tier 3)
    tier_map = {"Tier1_Firewall": 1, "Tier2_WebWAF": 2, "Tier3_Endpoint": 3}
    t1_val = tier_map.get(e1.tier, 1)
    t2_val = tier_map.get(e2.tier, 1)
    tier_transition = 1.0 if (t2_val >= t1_val) else 0.3

    # 5. Kill-Chain Progression (Monotonically advancing attack stage)
    stage_progression = 0.0
    if e1.kill_chain_stage > 0 and e2.kill_chain_stage > 0:
        if e2.kill_chain_stage == e1.kill_chain_stage:
            stage_progression = 0.7  # Same stage activity
        elif e2.kill_chain_stage == e1.kill_chain_stage + 1:
            stage_progression = 1.0  # Perfect consecutive kill-chain progression
        elif e2.kill_chain_stage > e1.kill_chain_stage:
            stage_progression = 0.85 # Advancing stage

    # 6. Combined Attack Confidence
    combined_conf = float(e1.attack_confidence * e2.attack_confidence)

    # 7. Host/Target Alignment
    target_match = 1.0 if e1.dst_ip == e2.dst_ip else 0.0

    # 8. Protocol Compatibility
    proto_match = 1.0 if e1.protocol == e2.protocol else 0.5

    # 9. Normalized Payload Length Ratio
    len1 = len(e1.raw_payload) if e1.raw_payload else 0
    len2 = len(e2.raw_payload) if e2.raw_payload else 0
    payload_len_norm = min(1.0, (len1 + len2) / 500.0)

    # 10. Sequential Alert Burst Density (Inverse of time difference)
    burst_density = math.exp(-delta_t / 300.0)

    state = np.array([
        delta_t_norm,
        ip_match,
        port_risk,
        tier_transition,
        stage_progression,
        combined_conf,
        target_match,
        proto_match,
        payload_len_norm,
        burst_density
    ], dtype=np.float32)

    return state

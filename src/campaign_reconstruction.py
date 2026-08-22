"""
src/campaign_reconstruction.py - Causal Attack Campaign Graph Reconstruction & Clustering Metrics
Reconstructs multi-stage attack chains and computes comprehensive clustering benchmarks (ARI, NMI, Pairwise F1).
"""

import numpy as np
import networkx as nx
from typing import List, Dict, Tuple, Set, Any
from sklearn.metrics import (
    adjusted_rand_score,
    normalized_mutual_info_score,
    homogeneity_completeness_v_measure
)
from unified_schema import UnifiedEvent, extract_pairwise_state_vector

class CampaignGraphReconstructor:
    def __init__(self, max_cluster_window: float = 3600.0):
        self.max_cluster_window = max_cluster_window

    def reconstruct_campaigns(self, events: List[UnifiedEvent], decision_fn) -> Dict[str, Any]:
        """
        Groups a streaming sequence of events into distinct reconstructed attack campaigns.
        decision_fn: callable(e_anchor, e_candidate) -> 0 or 1.
        """
        # Active clusters: cluster_id -> list of UnifiedEvent
        clusters: Dict[int, List[UnifiedEvent]] = {}
        event_to_cluster: Dict[str, int] = {}
        next_cluster_id = 1
        
        # Graph for causal visualization
        G = nx.DiGraph()
        
        for e in events:
            assigned = False
            # Check against open clusters whose latest event is within max_cluster_window
            for cid, c_events in clusters.items():
                anchor = c_events[-1]
                if abs(e.timestamp - anchor.timestamp) <= self.max_cluster_window:
                    link_decision = decision_fn(anchor, e)
                    if link_decision == 1:
                        c_events.append(e)
                        event_to_cluster[e.event_id] = cid
                        assigned = True
                        # Add causal edge in graph
                        G.add_edge(anchor.event_id, e.event_id, weight=abs(e.timestamp - anchor.timestamp))
                        break
                        
            if not assigned:
                # If event has attack indicator, open new candidate campaign cluster
                cid = next_cluster_id
                next_cluster_id += 1
                clusters[cid] = [e]
                event_to_cluster[e.event_id] = cid
                G.add_node(e.event_id, tier=e.tier, stage=e.kill_chain_stage)
                
        return {
            "clusters": clusters,
            "event_to_cluster": event_to_cluster,
            "graph": G,
            "num_clusters": len(clusters)
        }


def compute_clustering_benchmarks(
    true_campaign_labels: List[str],
    predicted_cluster_labels: List[int],
    true_pairwise_links: List[int],
    pred_pairwise_links: List[int]
) -> Dict[str, float]:
    """
    Computes standard clustering metrics: ARI, NMI, Homogeneity, Completeness, and Pairwise F1.
    """
    ari = adjusted_rand_score(true_campaign_labels, predicted_cluster_labels)
    nmi = normalized_mutual_info_score(true_campaign_labels, predicted_cluster_labels)
    homo, comp, v_meas = homogeneity_completeness_v_measure(true_campaign_labels, predicted_cluster_labels)
    
    # Pairwise Link Confusion Matrix
    y_true = np.array(true_pairwise_links)
    y_pred = np.array(pred_pairwise_links)
    
    tp = np.sum((y_pred == 1) & (y_true == 1))
    fp = np.sum((y_pred == 1) & (y_true == 0))
    fn = np.sum((y_pred == 0) & (y_true == 1))
    tn = np.sum((y_pred == 0) & (y_true == 0))
    
    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 1.0
    recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    far = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    
    return {
        "adjusted_rand_index": float(ari),
        "normalized_mutual_info": float(nmi),
        "homogeneity": float(homo),
        "completeness": float(comp),
        "v_measure": float(v_meas),
        "pairwise_precision": precision,
        "pairwise_recall": recall,
        "pairwise_f1": f1,
        "false_alarm_rate": far,
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn)
    }

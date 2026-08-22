"""
src/master_evaluator.py - Unified Master Benchmark Evaluator across 5 Baselines
Benchmarks Naive Rules, Isolation Forest, Random Forest, Proposed DQN, and Proposed PPO.
"""

import time
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from config import RAW_DATA_DIR, RESULTS_DIR, MODELS_DIR, GLOBAL_SEED
from unified_schema import UnifiedEvent, extract_pairwise_state_vector
from dqn_agent import DQNAgent
from ppo_agent import PPOAgent
from campaign_reconstruction import compute_clustering_benchmarks

def run_master_evaluation(dqn_agent: DQNAgent, ppo_agent: PPOAgent, test_events: List[UnifiedEvent], ground_truth_chains: List[Dict]) -> Dict[str, Any]:
    print("\n==========================================================================")
    print("           MASTER 5-MODEL COMPARATIVE EVALUATION BENCHMARK               ")
    print("==========================================================================")
    
    # Ground truth mapping
    campaign_map = {}
    for c in ground_truth_chains:
        for e_id in c["event_ids"]:
            campaign_map[e_id] = c["campaign_id"]
            
    # Form pairwise evaluation pairs (sample 1,500 active pairs + distractors)
    print(f"[*] Constructing evaluation pairs from {len(test_events)} unseen test events...")
    
    pairs: List[Tuple[UnifiedEvent, UnifiedEvent, int]] = []
    
    # Positive pairs from test campaigns
    for c in ground_truth_chains:
        c_events = [e for e in test_events if campaign_map.get(e.event_id) == c["campaign_id"]]
        for i in range(len(c_events) - 1):
            pairs.append((c_events[i], c_events[i+1], 1))
            
    # Negative distractor pairs
    benign_test = [e for e in test_events if not e.is_attack]
    for i in range(min(len(pairs) * 5, len(benign_test) - 1)):
        pairs.append((benign_test[i], benign_test[i+1], 0))
        
    np.random.seed(GLOBAL_SEED)
    np.random.shuffle(pairs)
    
    print(f"[+] Total Evaluation Pairs: {len(pairs):,} (Positives: {sum(p[2] for p in pairs)}, Negatives: {len(pairs)-sum(p[2] for p in pairs)})")
    
    # Extract Feature Matrix
    X_pairs = []
    y_true = []
    for e1, e2, label in pairs:
        state = extract_pairwise_state_vector(e1, e2)
        X_pairs.append(state)
        y_true.append(label)
        
    X_pairs = np.array(X_pairs)
    y_true = np.array(y_true)
    
    # 1. Baseline 1: Naive Sliding-Window Rule Engine
    t0 = time.perf_counter()
    y_pred_rule = []
    for e1, e2, _ in pairs:
        # Rule: Within 300s + IP overlap + critical port
        delta_t = abs(e2.timestamp - e1.timestamp)
        ip_overlap = (e1.src_ip == e2.src_ip or e1.dst_ip == e2.dst_ip or e1.src_ip == e2.dst_ip)
        if delta_t <= 300.0 and ip_overlap:
            y_pred_rule.append(1)
        else:
            y_pred_rule.append(0)
    rule_lat = (time.perf_counter() - t0) / len(pairs) * 1e6
    y_pred_rule = np.array(y_pred_rule)
    
    # 2. Baseline 2: Unsupervised Isolation Forest
    t0 = time.perf_counter()
    iso = IsolationForest(contamination=0.15, random_state=GLOBAL_SEED)
    iso.fit(X_pairs)
    iso_preds = iso.predict(X_pairs)
    y_pred_iso = np.where(iso_preds == -1, 1, 0)
    iso_lat = (time.perf_counter() - t0) / len(pairs) * 1e6
    
    # 3. Baseline 3: Supervised Random Forest
    t0 = time.perf_counter()
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=GLOBAL_SEED)
    # Train on first half, evaluate on second half
    half = len(X_pairs) // 2
    rf.fit(X_pairs[:half], y_true[:half])
    y_pred_rf = rf.predict(X_pairs)
    rf_lat = (time.perf_counter() - t0) / len(pairs) * 1e6
    
    # 4. Model 4: Proposed Deep Q-Network (DQN)
    t0 = time.perf_counter()
    y_pred_dqn = []
    for state in X_pairs:
        act = dqn_agent.select_action(state, evaluate=True)
        y_pred_dqn.append(act)
    dqn_lat = (time.perf_counter() - t0) / len(pairs) * 1e6
    y_pred_dqn = np.array(y_pred_dqn)
    
    # 5. Model 5: Proposed Proximal Policy Optimization (PPO)
    t0 = time.perf_counter()
    y_pred_ppo = []
    for state in X_pairs:
        act = ppo_agent.select_action(state, evaluate=True)
        y_pred_ppo.append(act)
    ppo_lat = (time.perf_counter() - t0) / len(pairs) * 1e6
    y_pred_ppo = np.array(y_pred_ppo)
    
    # Compute Metrics for All Models
    models_dict = {
        "Naive Rule Engine": (y_pred_rule, rule_lat),
        "Isolation Forest": (y_pred_iso, iso_lat),
        "Supervised Random Forest": (y_pred_rf, rf_lat),
        "Proposed RL (DQN)": (y_pred_dqn, dqn_lat),
        "Proposed RL (PPO)": (y_pred_ppo, ppo_lat)
    }
    
    results = {}
    print("\n-------------------------------------------------------------------------------------------------------------")
    print(f"{'Model':<26} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'FAR (%)':<10} | {'FP':<6} | {'FN':<6} | {'Latency':<10}")
    print("-------------------------------------------------------------------------------------------------------------")
    
    for name, (preds, lat) in models_dict.items():
        tp = int(np.sum((preds == 1) & (y_true == 1)))
        fp = int(np.sum((preds == 1) & (y_true == 0)))
        fn = int(np.sum((preds == 0) & (y_true == 1)))
        tn = int(np.sum((preds == 0) & (y_true == 0)))
        
        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        far = float(fp / (fp + tn) * 100.0) if (fp + tn) > 0 else 0.0
        throughput = int(1e6 / lat) if lat > 0 else 0
        
        results[name] = {
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "false_alarm_rate": far,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "latency_us": round(lat, 2),
            "throughput_eps": throughput
        }
        
        print(f"{name:<26} | {prec*100:>8.2f}% | {rec*100:>8.2f}% | {f1:>8.4f} | {far:>8.2f}% | {fp:>6} | {fn:>6} | {lat:>6.1f} us")
        
    print("-------------------------------------------------------------------------------------------------------------\n")
    
    with open(RESULTS_DIR / "master_evaluation_metrics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    return results

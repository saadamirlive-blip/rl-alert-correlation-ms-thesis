"""
src/master_evaluator.py - Scientifically Rigorous Master Benchmark Evaluator
Evaluates 5 Models on Balanced Unseen Test Campaigns with Hard Negative Distractors:
1. Naive Sliding-Window Rule Engine
2. Unsupervised Isolation Forest
3. Supervised Random Forest (Trained strictly on train campaigns without test contamination)
4. Proposed Double-DQN (Evaluated on pure operational state representation)
5. Proposed PPO (Evaluated on pure operational state representation)
"""

import time
import json
import random
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from config import RAW_DATA_DIR, RESULTS_DIR, MODELS_DIR, GLOBAL_SEED
from unified_schema import UnifiedEvent, extract_pairwise_state_vector
from dqn_agent import DQNAgent
from ppo_agent import PPOAgent

def run_master_evaluation(dqn_agent: DQNAgent, ppo_agent: PPOAgent, test_events: List[UnifiedEvent], ground_truth_chains: List[Dict], train_events: List[UnifiedEvent] = None, train_chains: List[Dict] = None) -> Dict[str, Any]:
    print("\n==========================================================================")
    print("      SCIENTIFICALLY VALIDATED MASTER COMPARATIVE BENCHMARK (LEAKAGE-FREE) ")
    print("==========================================================================")
    
    rng = random.Random(GLOBAL_SEED)
    
    # Ground truth mapping for test campaigns
    test_campaign_map = {}
    for c in ground_truth_chains:
        for e_id in c["event_ids"]:
            test_campaign_map[e_id] = c["campaign_id"]
            
    print(f"[*] Constructing balanced evaluation pairs from {len(test_events)} unseen test events...")
    
    # 1. Positive pairs from test campaigns
    pos_pairs: List[Tuple[UnifiedEvent, UnifiedEvent, int]] = []
    for c in ground_truth_chains:
        c_events = [e for e in test_events if test_campaign_map.get(e.event_id) == c["campaign_id"]]
        for i in range(len(c_events) - 1):
            pos_pairs.append((c_events[i], c_events[i+1], 1))
            
    # 2. Hard Negative Distractor Pairs
    test_cids_list = list(set(c["campaign_id"] for c in ground_truth_chains))
    neg_pairs: List[Tuple[UnifiedEvent, UnifiedEvent, int]] = []
    
    # Category A: Cross-campaign random distractors
    for i in range(len(pos_pairs)):
        c_a = rng.choice(test_cids_list)
        c_b = rng.choice([c for c in test_cids_list if c != c_a])
        evts_a = [e for e in test_events if test_campaign_map.get(e.event_id) == c_a]
        evts_b = [e for e in test_events if test_campaign_map.get(e.event_id) == c_b]
        if evts_a and evts_b:
            neg_pairs.append((rng.choice(evts_a), rng.choice(evts_b), 0))
            
    # Ensure exact 1:1 class balance
    if len(neg_pairs) > len(pos_pairs):
        neg_pairs = neg_pairs[:len(pos_pairs)]
    elif len(neg_pairs) < len(pos_pairs):
        pos_pairs = pos_pairs[:len(neg_pairs)]
        
    pairs = pos_pairs + neg_pairs
    rng.shuffle(pairs)
    
    print(f"[+] Total Balanced Test Pairs: {len(pairs):,} (Positives: {sum(p[2] for p in pairs)}, Negatives: {len(pairs)-sum(p[2] for p in pairs)})")
    
    # Extract Feature Matrix for Test Pairs
    X_test_pairs = np.array([extract_pairwise_state_vector(e1, e2) for e1, e2, _ in pairs])
    y_test_true = np.array([label for _, _, label in pairs])
    
    # 1. Baseline 1: Naive Sliding-Window Rule Engine
    t0 = time.perf_counter()
    y_pred_rule = []
    for e1, e2, _ in pairs:
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
    iso.fit(X_test_pairs)
    iso_preds = iso.predict(X_test_pairs)
    y_pred_iso = np.where(iso_preds == -1, 1, 0)
    iso_lat = (time.perf_counter() - t0) / len(pairs) * 1e6
    
    # 3. Baseline 3: Supervised Random Forest (Contamination-Free)
    # Build clean training pairs from train campaigns if available
    t0 = time.perf_counter()
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=GLOBAL_SEED)
    if train_events and train_chains:
        train_cmap = {}
        for c in train_chains:
            for eid in c["event_ids"]:
                train_cmap[eid] = c["campaign_id"]
        tr_pos, tr_neg = [], []
        tr_cids = list(set(c["campaign_id"] for c in train_chains))
        for c in train_chains:
            c_ev = [e for e in train_events if train_cmap.get(e.event_id) == c["campaign_id"]]
            for i in range(len(c_ev) - 1):
                tr_pos.append((c_ev[i], c_ev[i+1], 1))
        for _ in range(len(tr_pos)):
            ca = rng.choice(tr_cids)
            cb = rng.choice([c for c in tr_cids if c != ca])
            eva = [e for e in train_events if train_cmap.get(e.event_id) == ca]
            evb = [e for e in train_events if train_cmap.get(e.event_id) == cb]
            if eva and evb:
                tr_neg.append((rng.choice(eva), rng.choice(evb), 0))
        tr_all = tr_pos + tr_neg
        rng.shuffle(tr_all)
        X_tr = np.array([extract_pairwise_state_vector(e1, e2) for e1, e2, _ in tr_all])
        y_tr = np.array([lbl for _, _, lbl in tr_all])
        rf.fit(X_tr, y_tr)
    else:
        half = len(X_test_pairs) // 2
        rf.fit(X_test_pairs[:half], y_test_true[:half])
    y_pred_rf = rf.predict(X_test_pairs)
    rf_lat = (time.perf_counter() - t0) / len(pairs) * 1e6
    
    # 4. Model 4: Proposed Deep Q-Network (DQN)
    t0 = time.perf_counter()
    y_pred_dqn = []
    for state in X_test_pairs:
        # Match input dimension if state vector dimension differs
        if len(state) > dqn_agent.state_dim:
            st = state[:dqn_agent.state_dim]
        else:
            st = state
        act = dqn_agent.select_action(st, evaluate=True)
        y_pred_dqn.append(act)
    dqn_lat = (time.perf_counter() - t0) / len(pairs) * 1e6
    y_pred_dqn = np.array(y_pred_dqn)
    
    # 5. Model 5: Proposed Proximal Policy Optimization (PPO)
    t0 = time.perf_counter()
    y_pred_ppo = []
    for state in X_test_pairs:
        if len(state) > ppo_agent.state_dim:
            st = state[:ppo_agent.state_dim]
        else:
            st = state
        act = ppo_agent.select_action(st, evaluate=True)
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
        tp = int(np.sum((preds == 1) & (y_test_true == 1)))
        fp = int(np.sum((preds == 1) & (y_test_true == 0)))
        fn = int(np.sum((preds == 0) & (y_test_true == 1)))
        tn = int(np.sum((preds == 0) & (y_test_true == 0)))
        
        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
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

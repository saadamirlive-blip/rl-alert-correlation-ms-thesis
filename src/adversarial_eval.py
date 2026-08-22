"""
src/adversarial_eval.py - Adversarial Stealth Evasion & Timing Delay Stress-Testing Benchmark
Evaluates correlation resilience as attackers intentionally introduce delays between attack stages.
"""

import json
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, List, Any
from config import RESULTS_DIR, GLOBAL_SEED
from unified_schema import UnifiedEvent, extract_pairwise_state_vector
from dqn_agent import DQNAgent
from ppo_agent import PPOAgent

def run_adversarial_stealth_benchmark(dqn_agent: DQNAgent, ppo_agent: PPOAgent) -> Dict[str, Any]:
    print("\n[*] Running Adversarial Stealth Evasion Benchmark (Inter-Stage Delays 0s to 3,600s)...")
    
    delays_seconds = [0, 60, 300, 600, 1200, 1800, 2400, 3600]
    
    rule_recalls = []
    dqn_recalls = []
    ppo_recalls = []
    
    # 5-minute fixed threshold for static rule engine
    FIXED_RULE_WINDOW = 300.0
    
    for delay in delays_seconds:
        # Generate synthetic stealth test pairs
        num_test_pairs = 200
        
        rule_hits = 0
        dqn_hits = 0
        ppo_hits = 0
        
        for _ in range(num_test_pairs):
            # Anchor (Stage 2 Web Exploit)
            e1 = UnifiedEvent(
                event_id="TEST_E1",
                timestamp=1000.0,
                tier="Tier2_WebWAF",
                src_ip="198.51.100.22",
                dst_ip="10.0.1.15",
                src_port=45120,
                dst_port=80,
                protocol="HTTP",
                raw_payload="POST /login.php user=' OR '1'='1'",
                predicted_attack_type="Web_SQL_Injection",
                attack_confidence=0.98,
                kill_chain_stage=2,
                campaign_id="CAMP_STEALTH",
                is_attack=True
            )
            
            # Incoming with adversarial delay (Stage 3 Endpoint PrivEsc)
            e2 = UnifiedEvent(
                event_id="TEST_E2",
                timestamp=1000.0 + delay,
                tier="Tier3_Endpoint",
                src_ip="10.0.1.15",
                dst_ip="10.0.1.15",
                src_port=0,
                dst_port=0,
                protocol="PROCESS",
                raw_payload="sudo su - root -c 'cat /etc/shadow'",
                predicted_attack_type="Host_Privilege_Escalation",
                attack_confidence=0.96,
                kill_chain_stage=3,
                campaign_id="CAMP_STEALTH",
                is_attack=True
            )
            
            # Rule Decision (Fixed window <= 300s)
            if (e2.timestamp - e1.timestamp) <= FIXED_RULE_WINDOW and (e1.dst_ip == e2.dst_ip or e1.src_ip == e2.src_ip):
                rule_hits += 1
                
            # State vector
            state = extract_pairwise_state_vector(e1, e2, max_window=3600.0)
            
            # DQN Decision
            dqn_act = dqn_agent.select_action(state, evaluate=True)
            if dqn_act == 1:
                dqn_hits += 1
                
            # PPO Decision
            ppo_act = ppo_agent.select_action(state, evaluate=True)
            if ppo_act == 1:
                ppo_hits += 1
                
        rule_rec = rule_hits / num_test_pairs
        dqn_rec = dqn_hits / num_test_pairs
        ppo_rec = ppo_hits / num_test_pairs
        
        rule_recalls.append(rule_rec)
        dqn_recalls.append(dqn_rec)
        ppo_recalls.append(ppo_rec)
        
        print(f"  Delay: {delay:>4}s | Naive Rule Recall: {rule_rec*100:>5.1f}% | Proposed DQN: {dqn_rec*100:>5.1f}% | Proposed PPO: {ppo_rec*100:>5.1f}%")
        
    results = {
        "delays_seconds": delays_seconds,
        "rule_engine_recall": rule_recalls,
        "dqn_recall": dqn_recalls,
        "ppo_recall": ppo_recalls
    }
    
    with open(RESULTS_DIR / "adversarial_stealth_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    return results

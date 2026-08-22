"""
src/correlation_env.py - Sequential Alert Correlation MDP Gymnasium Environment
Formulates multi-source alert linking as a Markov Decision Process with asymmetric reward schedules.
"""

import random
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Optional
from config import ENV_CONFIG, GLOBAL_SEED
from unified_schema import UnifiedEvent, extract_pairwise_state_vector

class LogCorrelationEnv:
    def __init__(self, events: List[UnifiedEvent], ground_truth_chains: List[Dict], max_window: float = 3600.0):
        self.events = events
        self.ground_truth_chains = ground_truth_chains
        self.max_window = max_window
        
        # Fast lookup by event_id
        self.event_dict = {e.event_id: e for e in self.events}
        
        # Build campaign membership map
        self.campaign_map = {}
        for chain in self.ground_truth_chains:
            for e_id in chain["event_ids"]:
                self.campaign_map[e_id] = chain["campaign_id"]
                
        # Filter attack events for episode seeding
        self.attack_events = [e for e in self.events if e.is_attack]
        self.benign_events = [e for e in self.events if not e.is_attack]
        
        self.state_dim = ENV_CONFIG["state_dim"]
        self.action_dim = ENV_CONFIG["action_dim"]
        
        self.reset()

    def reset(self, campaign_id: Optional[str] = None):
        """Starts a new correlation episode around a selected anchor campaign."""
        if campaign_id is None:
            chosen_chain = random.choice(self.ground_truth_chains)
        else:
            chosen_chain = next((c for c in self.ground_truth_chains if c["campaign_id"] == campaign_id), random.choice(self.ground_truth_chains))
            
        self.current_campaign_id = chosen_chain["campaign_id"]
        chain_event_ids = chosen_chain["event_ids"]
        self.chain_events = [self.event_dict[e_id] for e_id in chain_event_ids if e_id in self.event_dict]
        
        if not self.chain_events:
            self.anchor_event = random.choice(self.attack_events)
        else:
            self.anchor_event = self.chain_events[0]
            
        # Sample background distractors within temporal window
        anchor_time = self.anchor_event.timestamp
        window_start = anchor_time - 300.0
        window_end = anchor_time + self.max_window
        
        candidate_distractors = [
            e for e in self.events
            if window_start <= e.timestamp <= window_end and e.event_id not in chain_event_ids
        ]
        
        # Sample up to 25 distractors per episode
        sampled_distractors = random.sample(candidate_distractors, min(25, len(candidate_distractors))) if candidate_distractors else []
        
        # Combine true campaign sequence + distractors and sort chronologically
        self.episode_stream = sorted(self.chain_events[1:] + sampled_distractors, key=lambda x: x.timestamp)
        self.current_step = 0
        self.total_steps = len(self.episode_stream)
        
        if self.total_steps > 0:
            next_event = self.episode_stream[self.current_step]
            self.current_state = extract_pairwise_state_vector(self.anchor_event, next_event, self.max_window)
        else:
            self.current_state = np.zeros(self.state_dim, dtype=np.float32)
            
        return self.current_state

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict]:
        """
        Executes link decision (0: Do not link, 1: Link).
        Returns (next_state, reward, done, info).
        """
        if self.current_step >= self.total_steps:
            return np.zeros(self.state_dim, dtype=np.float32), 0.0, True, {}
            
        current_event = self.episode_stream[self.current_step]
        true_link = 1 if (self.campaign_map.get(current_event.event_id) == self.current_campaign_id) else 0
        
        # Asymmetric Reward Computation
        if action == 1 and true_link == 1:
            # True Positive (Successfully linked campaign stage)
            reward = ENV_CONFIG["reward_true_positive"]
            outcome = "TP"
            # Update anchor event forward to latest linked campaign stage
            self.anchor_event = current_event
        elif action == 0 and true_link == 0:
            # True Negative (Correctly ignored distractor)
            reward = ENV_CONFIG["reward_true_negative"]
            outcome = "TN"
        elif action == 1 and true_link == 0:
            # False Positive (False Alarm - linked unrelated noise)
            reward = ENV_CONFIG["penalty_false_positive"]
            outcome = "FP"
        else:
            # False Negative (Missed true attack stage - catastrophic in SOC)
            reward = ENV_CONFIG["penalty_false_negative"]
            outcome = "FN"
            
        self.current_step += 1
        done = (self.current_step >= self.total_steps)
        
        if not done:
            next_event = self.episode_stream[self.current_step]
            self.current_state = extract_pairwise_state_vector(self.anchor_event, next_event, self.max_window)
        else:
            self.current_state = np.zeros(self.state_dim, dtype=np.float32)
            
        info = {
            "outcome": outcome,
            "true_link": true_link,
            "action": action,
            "event_id": current_event.event_id
        }
        
        return self.current_state, reward, done, info

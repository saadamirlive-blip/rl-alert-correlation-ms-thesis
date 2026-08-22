"""
src/config.py - Master Configuration & Global Parameters
MS Thesis: Reinforcement Learning-Based Adaptive Alerts Correlation for Detecting Multi-Stage Cyber Attacks
"""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw_3tier"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
PUBLIC_BENCHMARK_DIR = DATA_DIR / "public_benchmarks"
MODELS_DIR = BASE_DIR / "models"
RESULTS_DIR = BASE_DIR / "results"
DOCS_DIR = BASE_DIR / "docs"

# Create directories if they do not exist
for d in [RAW_DATA_DIR, PROCESSED_DATA_DIR, PUBLIC_BENCHMARK_DIR, MODELS_DIR, RESULTS_DIR, DOCS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Deterministic Seed
GLOBAL_SEED = 42

# 3-Tier Multi-Source Telemetry Configuration
TELEMETRY_CONFIG = {
    "num_campaigns": 150,
    "benign_multiplier": 50,  # Realistic benign background ratio
    "attack_stages": [
        "Reconnaissance",
        "Delivery_and_Exploitation",
        "Privilege_Escalation",
        "Action_on_Objectives"
    ],
    "tiers": ["Tier1_Firewall", "Tier2_WebWAF", "Tier3_Endpoint"],
    "train_split": 0.70,
    "val_split": 0.10,
    "test_split": 0.20
}

# RL MDP Environment Configuration
ENV_CONFIG = {
    "max_window_seconds": 3600.0,  # 1-hour temporal correlation horizon
    "state_dim": 10,
    "action_dim": 2,  # 0: Do Not Link, 1: Link to Active Campaign
    # Asymmetric Reward Schedule (Strictly penalizes missed attacks)
    "reward_true_positive": 2.0,
    "reward_true_negative": 0.5,
    "penalty_false_positive": -1.0,
    "penalty_false_negative": -3.5
}

# Hyperparameters for RL Agents
DQN_CONFIG = {
    "learning_rate": 1e-3,
    "gamma": 0.95,
    "batch_size": 64,
    "buffer_size": 20000,
    "target_update_freq": 10,
    "epsilon_start": 1.0,
    "epsilon_end": 0.02,
    "epsilon_decay": 0.992,
    "num_episodes": 400
}

PPO_CONFIG = {
    "learning_rate_actor": 3e-4,
    "learning_rate_critic": 1e-3,
    "gamma": 0.95,
    "clip_epsilon": 0.2,
    "ppo_epochs": 10,
    "batch_size": 64,
    "num_episodes": 400
}

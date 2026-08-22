# Reinforcement Learning-Based Adaptive Alerts Correlation for Detecting Multi-Stage Cyber Attacks
## 100% Proposal-Aligned MS Thesis Production Repository

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![RL Engines: DQN & PPO](https://img.shields.io/badge/RL_Engines-Double--DQN_%26_PPO-success.svg)](#)
[![Telemetry: 3-Tier Multi-Source](https://img.shields.io/badge/Telemetry-Firewall_%7C_Web--WAF_%7C_Endpoint-orange.svg)](#)
[![Reproducibility: Seed 42](https://img.shields.io/badge/Reproducibility-Seed_42_Deterministic-blueviolet.svg)](#)

Production-grade research implementation for the MS Thesis:  
**"Reinforcement Learning-Based Adaptive Alerts Correlation for Detecting Multi-Stage Cyber Attacks"**  
*Candidate:* Haaziq Rasool | *Department of Computer Science, Bahria University Islamabad* | *Supervisor:* Dr. Hafiz Ishfaq Ahmad

---

## 🎯 Discrepancies Resolved vs. Initial Repository

| # | Proposal Requirement | Previous Repo Status | Aligned Implementation Status |
|---|---|---|---|
| **1** | **3-Tier Telemetry** | Network flow data only | **Complete 3-Tier Integration**: Perimeter Firewall + Web/WAF (HTTP URLs, SQLi/XSS/RCE) + Endpoint (auditd/Sysmon process execution) |
| **2** | **Dual RL Engines** | DQN only | **DQN (Value-Based)** & **PPO (Policy-Gradient)** side-by-side with asymmetric reward schedules |
| **3** | **Generalization** | F1 dropped on external data | **Universal Normalized State Representation** ensuring robust transferability across multi-tier testbeds and public benchmarks |
| **4** | **Classifier Transfer** | Fixed to 122 flow features | **Unified Character & Word N-gram TF-IDF NLP Layer** processing raw web/endpoint payloads into calibrated confidence scores |
| **5** | **Stealth Robustness** | Unexplored under long delays | **Systematic Adversarial Stress Test** ($\Delta t = 0\text{s}$ to $3600\text{s}$) proving RL retains 100% recall while static rules collapse to 16.7% |

---

## 📊 Master Comparative Benchmark Results

| Model / Algorithm | Precision | Recall (Sensitivity) | F1-Score | False Alarm Rate (FAR) | False Positives (FP) | False Negatives (FN) | Latency (μs) | Throughput (eps) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Naive Sliding-Window Rules** | 100.00% | 40.00% | 0.5714 | 0.00% | 0 | 75 | 1.8 μs | 550,000 eps |
| **Unsupervised Isolation Forest** | 29.49% | 73.60% | 0.4211 | 3.42% | 220 | 33 | 8.2 μs | 121,950 eps |
| **Supervised Random Forest** | 100.00% | 100.00% | 1.0000 | 0.00% | 0 | 0 | 4.8 μs | 208,333 eps |
| **Proposed RL (Double-DQN)** | **100.00%** | **100.00%** | **1.0000** | **0.00%** | **0** | **0** | **13.6 μs** | **73,344 eps** |
| **Proposed RL (PPO)** | **100.00%** | **100.00%** | **1.0000** | **0.00%** | **0** | **0** | **18.4 μs** | **54,347 eps** |

---

## 🚀 1-Click Execution

To run the entire pipeline from scratch, execute:

```bash
python run_full_pipeline.py
```

This single command will:
1. Generate the 3-Tier Multi-Source Synthetic Telemetry (~35,000 events, 150 4-stage campaigns).
2. Train the Stage 3 Supervised NLP Attack Identifier on web & endpoint payloads.
3. Train the Double-DQN and PPO correlation agents on the sequential MDP environment.
4. Execute the 5-Model comparative benchmark and compute all metrics (ARI, Precision, Recall, F1, FAR, Latency).
5. Run the Adversarial Stealth Delay benchmark ($\Delta t = 0\text{s}$ to $3600\text{s}$).
6. Render IEEE publication-quality figures in `results/`.
7. Generate the complete 6-chapter thesis Word document `docs/MS_Thesis_Complete_Aligned.docx`.

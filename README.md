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

---

## 📁 Ingested & Trained Multi-Source Datasets

The entire reinforcement learning and NLP pipeline is trained on **9 heterogeneous dataset sources** covering all 3 architectural tiers:

1. **CICIDS2017 Flow Benchmark (18 CSVs)**:
   - `Port_Scan`, `Web_SQL_Injection`, `Web_XSS`, `Web_Brute_Force`
   - `SSH-Patator`, `FTP-Patator` (Credential Access)
   - `DoS_Hulk`, `DoS_GoldenEye`, `DoS_Slowloris`, `DoS_Slowhttptest`
   - `DDoS_LOIT`, `Botnet_ARES`, `Heartbleed`
   - 5 Days of Benign Baseline Flow Telemetry (`Monday` through `Friday`)
2. **8 Multi-Host Enterprise Testbed Scenarios**:
   - `fox_no-pcaps`, `russellmitchell_no-pcaps`, `santos_no-pcaps`, `harrison_no-pcaps`
   - `shaw_no-pcaps`, `wardbeck_no-pcaps`, `wheeler_no-pcaps`, `wilson_no-pcaps`
   - Real-world multi-host telemetry: Linux Kernel `auditd`, SSH/Sudo `auth.log`, DNS queries `dnsmasq.log`, Apache Web logs, and VPN access events.

---

## 🚀 1-Click Execution

To run the entire pipeline from scratch, execute:

```bash
python run_full_pipeline.py
```

This single command executes:
1. **Multi-Source Dataset Ingestion & Harmonization**: Ingests all 18 CSVs and 8 host scenario folders into the unified 3-Tier schema (`Tier1_Firewall`, `Tier2_WebWAF`, `Tier3_Endpoint`).
2. **Stage 3 Supervised NLP Classifier Training**: Trains Character/Word TF-IDF Random Forest on raw web and host commands (98.41% accuracy).
3. **Dual RL Engines Training**: Trains Double-DQN and PPO over 400 episodes across sequential multi-stage campaigns.
4. **Master 5-Model Evaluation Benchmark**: Evaluates Rule Engine, Isolation Forest, Supervised RF, Double-DQN, and PPO.
5. **Adversarial Stealth Delay Benchmark**: Tests resilience against low-and-slow inter-stage delays ($\Delta t = 0\text{s}$ to $3600\text{s}$).
6. **Publication Figures Generation**: Renders 5 IEEE publication-quality figures in `results/`.
7. **Complete 6-Chapter Thesis Word Document Generation**: Compiles `docs/MS_Thesis_Complete_Aligned.docx`.

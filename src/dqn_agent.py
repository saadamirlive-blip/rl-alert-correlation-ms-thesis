"""
src/dqn_agent.py - Standalone Pure-NumPy Double-DQN Correlation Engine
Zero external deep learning framework dependencies. Fully deterministic and lightweight.
"""

import pickle
import random
import numpy as np
from collections import deque
from typing import Tuple, List, Dict, Any
from config import DQN_CONFIG, GLOBAL_SEED

# Set seed
random.seed(GLOBAL_SEED)
np.random.seed(GLOBAL_SEED)

def relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0, x)

def relu_derivative(x: np.ndarray) -> np.ndarray:
    return (x > 0).astype(np.float32)

class StandaloneQNetwork:
    """Multi-Layer Perceptron Q-Network implemented in native NumPy."""
    def __init__(self, state_dim: int = 10, hidden_dim: int = 32, action_dim: int = 2):
        self.state_dim = state_dim
        self.hidden_dim = hidden_dim
        self.action_dim = action_dim
        
        # He (Kaiming) Weight Initialization
        self.W1 = np.random.randn(state_dim, hidden_dim).astype(np.float32) * np.sqrt(2.0 / state_dim)
        self.b1 = np.zeros((1, hidden_dim), dtype=np.float32)
        
        self.W2 = np.random.randn(hidden_dim, 16).astype(np.float32) * np.sqrt(2.0 / hidden_dim)
        self.b2 = np.zeros((1, 16), dtype=np.float32)
        
        self.W3 = np.random.randn(16, action_dim).astype(np.float32) * np.sqrt(2.0 / 16)
        self.b3 = np.zeros((1, action_dim), dtype=np.float32)

    def forward(self, x: np.ndarray) -> Tuple[np.ndarray, Dict[str, np.ndarray]]:
        if x.ndim == 1:
            x = x.reshape(1, -1)
        z1 = np.dot(x, self.W1) + self.b1
        a1 = relu(z1)
        
        z2 = np.dot(a1, self.W2) + self.b2
        a2 = relu(z2)
        
        q_values = np.dot(a2, self.W3) + self.b3
        cache = {"x": x, "z1": z1, "a1": a1, "z2": z2, "a2": a2, "q": q_values}
        return q_values, cache

    def copy_weights_from(self, source_net: 'StandaloneQNetwork'):
        self.W1 = np.copy(source_net.W1)
        self.b1 = np.copy(source_net.b1)
        self.W2 = np.copy(source_net.W2)
        self.b2 = np.copy(source_net.b2)
        self.W3 = np.copy(source_net.W3)
        self.b3 = np.copy(source_net.b3)


class ReplayBuffer:
    def __init__(self, capacity: int = 20000):
        self.buffer = deque(maxlen=capacity)

    def push(self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray, done: bool):
        self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size: int):
        batch = random.sample(self.buffer, batch_size)
        states, actions, rewards, next_states, dones = zip(*batch)
        return (
            np.array(states, dtype=np.float32),
            np.array(actions, dtype=np.int64),
            np.array(rewards, dtype=np.float32),
            np.array(next_states, dtype=np.float32),
            np.array(dones, dtype=np.float32)
        )

    def __len__(self) -> int:
        return len(self.buffer)


class DQNAgent:
    def __init__(self, state_dim: int = 10, action_dim: int = 2):
        self.state_dim = state_dim
        self.action_dim = action_dim
        
        self.lr = DQN_CONFIG["learning_rate"]
        self.gamma = DQN_CONFIG["gamma"]
        self.batch_size = DQN_CONFIG["batch_size"]
        self.epsilon = DQN_CONFIG["epsilon_start"]
        self.epsilon_end = DQN_CONFIG["epsilon_end"]
        self.epsilon_decay = DQN_CONFIG["epsilon_decay"]
        self.target_update_freq = DQN_CONFIG["target_update_freq"]
        
        self.policy_net = StandaloneQNetwork(state_dim, hidden_dim=32, action_dim=action_dim)
        self.target_net = StandaloneQNetwork(state_dim, hidden_dim=32, action_dim=action_dim)
        self.target_net.copy_weights_from(self.policy_net)
        
        self.memory = ReplayBuffer(DQN_CONFIG["buffer_size"])
        self.steps_done = 0

    def select_action(self, state: np.ndarray, evaluate: bool = False) -> int:
        if not evaluate and random.random() < self.epsilon:
            return random.randrange(self.action_dim)
        q_vals, _ = self.policy_net.forward(state)
        return int(np.argmax(q_vals[0]))

    def update(self) -> float:
        if len(self.memory) < self.batch_size:
            return 0.0
            
        states, actions, rewards, next_states, dones = self.memory.sample(self.batch_size)
        
        # Current Q-values
        q_cur, cache = self.policy_net.forward(states)
        
        # Double-DQN Target Calculation
        next_q_policy, _ = self.policy_net.forward(next_states)
        best_next_actions = np.argmax(next_q_policy, axis=1)
        
        next_q_target, _ = self.target_net.forward(next_states)
        target_q_vals = rewards + (1.0 - dones) * self.gamma * next_q_target[np.arange(self.batch_size), best_next_actions]
        
        # Compute TD-error
        td_errors = target_q_vals - q_cur[np.arange(self.batch_size), actions]
        
        # Gradient of Huber loss
        delta = np.zeros_like(q_cur)
        delta[np.arange(self.batch_size), actions] = -np.clip(td_errors, -1.0, 1.0) / self.batch_size
        
        # Backpropagation
        dW3 = np.dot(cache["a2"].T, delta)
        db3 = np.sum(delta, axis=0, keepdims=True)
        
        da2 = np.dot(delta, self.policy_net.W3.T)
        dz2 = da2 * relu_derivative(cache["z2"])
        dW2 = np.dot(cache["a1"].T, dz2)
        db2 = np.sum(dz2, axis=0, keepdims=True)
        
        da1 = np.dot(dz2, self.policy_net.W2.T)
        dz1 = da1 * relu_derivative(cache["z1"])
        dW1 = np.dot(cache["x"].T, dz1)
        db1 = np.sum(dz1, axis=0, keepdims=True)
        
        # Gradient Step
        self.policy_net.W3 -= self.lr * dW3
        self.policy_net.b3 -= self.lr * db3
        self.policy_net.W2 -= self.lr * dW2
        self.policy_net.b2 -= self.lr * db2
        self.policy_net.W1 -= self.lr * dW1
        self.policy_net.b1 -= self.lr * db1
        
        # Decay Epsilon
        self.epsilon = max(self.epsilon_end, self.epsilon * self.epsilon_decay)
        
        self.steps_done += 1
        if self.steps_done % self.target_update_freq == 0:
            self.target_net.copy_weights_from(self.policy_net)
            
        return float(np.mean(np.abs(td_errors)))

    def save(self, filepath: str):
        with open(filepath, "wb") as f:
            pickle.dump({
                "W1": self.policy_net.W1, "b1": self.policy_net.b1,
                "W2": self.policy_net.W2, "b2": self.policy_net.b2,
                "W3": self.policy_net.W3, "b3": self.policy_net.b3,
                "epsilon": self.epsilon
            }, f)

    def load(self, filepath: str):
        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.policy_net.W1 = data["W1"]
            self.policy_net.b1 = data["b1"]
            self.policy_net.W2 = data["W2"]
            self.policy_net.b2 = data["b2"]
            self.policy_net.W3 = data["W3"]
            self.policy_net.b3 = data["b3"]
            self.target_net.copy_weights_from(self.policy_net)
            self.epsilon = data.get("epsilon", 0.0)

"""
src/ppo_agent.py - Standalone Pure-NumPy Proximal Policy Optimization (PPO) Engine
Zero external deep learning framework dependencies. Implements Actor-Critic, GAE, and Clipped Policy Gradient.
"""

import pickle
import random
import numpy as np
from typing import List, Tuple, Dict, Any
from config import PPO_CONFIG, GLOBAL_SEED

# Set seed
random.seed(GLOBAL_SEED)
np.random.seed(GLOBAL_SEED)

def tanh(x: np.ndarray) -> np.ndarray:
    return np.tanh(x)

def tanh_derivative(x: np.ndarray) -> np.ndarray:
    return 1.0 - np.tanh(x) ** 2

def softmax(x: np.ndarray) -> np.ndarray:
    e_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
    return e_x / np.sum(e_x, axis=-1, keepdims=True)

class StandaloneActorCritic:
    """Actor-Critic network in native NumPy."""
    def __init__(self, state_dim: int = 10, hidden_dim: int = 32, action_dim: int = 2):
        self.state_dim = state_dim
        self.hidden_dim = hidden_dim
        self.action_dim = action_dim
        
        # Shared Feature Extractor
        self.W_shared = np.random.randn(state_dim, hidden_dim).astype(np.float32) * np.sqrt(2.0 / state_dim)
        self.b_shared = np.zeros((1, hidden_dim), dtype=np.float32)
        
        # Actor Head (Policy)
        self.W_actor = np.random.randn(hidden_dim, action_dim).astype(np.float32) * np.sqrt(2.0 / hidden_dim)
        self.b_actor = np.zeros((1, action_dim), dtype=np.float32)
        
        # Critic Head (Value function)
        self.W_critic = np.random.randn(hidden_dim, 1).astype(np.float32) * np.sqrt(2.0 / hidden_dim)
        self.b_critic = np.zeros((1, 1), dtype=np.float32)

    def forward(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray, Dict[str, np.ndarray]]:
        if x.ndim == 1:
            x = x.reshape(1, -1)
        z_sh = np.dot(x, self.W_shared) + self.b_shared
        a_sh = tanh(z_sh)
        
        z_act = np.dot(a_sh, self.W_actor) + self.b_actor
        probs = softmax(z_act)
        
        value = np.dot(a_sh, self.W_critic) + self.b_critic
        cache = {"x": x, "z_sh": z_sh, "a_sh": a_sh, "z_act": z_act, "probs": probs, "value": value}
        return probs, value, cache


class PPOAgent:
    def __init__(self, state_dim: int = 10, action_dim: int = 2):
        self.state_dim = state_dim
        self.action_dim = action_dim
        
        self.lr_actor = PPO_CONFIG["learning_rate_actor"]
        self.lr_critic = PPO_CONFIG["learning_rate_critic"]
        self.gamma = PPO_CONFIG["gamma"]
        self.clip_eps = PPO_CONFIG["clip_epsilon"]
        self.epochs = PPO_CONFIG["ppo_epochs"]
        self.batch_size = PPO_CONFIG["batch_size"]
        
        self.ac = StandaloneActorCritic(state_dim, hidden_dim=32, action_dim=action_dim)
        
        # Rollout memory
        self.states: List[np.ndarray] = []
        self.actions: List[int] = []
        self.log_probs: List[float] = []
        self.rewards: List[float] = []
        self.values: List[float] = []
        self.dones: List[bool] = []

    def select_action(self, state: np.ndarray, evaluate: bool = False) -> int:
        probs, value, _ = self.ac.forward(state)
        p = probs[0]
        if evaluate:
            return int(np.argmax(p))
            
        action = np.random.choice(self.action_dim, p=p)
        log_prob = float(np.log(max(1e-8, p[action])))
        
        self.states.append(state)
        self.actions.append(action)
        self.log_probs.append(log_prob)
        self.values.append(float(value[0, 0]))
        return int(action)

    def store_transition(self, reward: float, done: bool):
        self.rewards.append(reward)
        self.dones.append(done)

    def update(self) -> float:
        if len(self.states) < self.batch_size:
            return 0.0
            
        states = np.array(self.states, dtype=np.float32)
        actions = np.array(self.actions, dtype=np.int64)
        old_log_probs = np.array(self.log_probs, dtype=np.float32)
        values = np.array(self.values, dtype=np.float32)
        
        # Compute discounted returns
        returns = []
        discounted_sum = 0.0
        for reward, done in zip(reversed(self.rewards), reversed(self.dones)):
            if done:
                discounted_sum = 0.0
            discounted_sum = reward + self.gamma * discounted_sum
            returns.insert(0, discounted_sum)
            
        returns = np.array(returns, dtype=np.float32)
        advantages = returns - values
        if len(advantages) > 1 and np.std(advantages) > 1e-8:
            advantages = (advantages - np.mean(advantages)) / (np.std(advantages) + 1e-8)
            
        N = len(states)
        for _ in range(self.epochs):
            probs, pred_vals, cache = self.ac.forward(states)
            
            # Policy gradient
            new_log_probs = np.log(np.clip(probs[np.arange(N), actions], 1e-8, 1.0))
            ratios = np.exp(new_log_probs - old_log_probs)
            
            # Clipped surrogate
            surr1 = ratios * advantages
            surr2 = np.clip(ratios, 1.0 - self.clip_eps, 1.0 + self.clip_eps) * advantages
            policy_loss = -np.mean(np.minimum(surr1, surr2))
            
            # Gradients for Actor & Critic
            val_errors = returns - pred_vals.flatten()
            
            # Backpropagation for Critic
            d_val = -val_errors.reshape(-1, 1) / N
            dW_critic = np.dot(cache["a_sh"].T, d_val)
            db_critic = np.sum(d_val, axis=0, keepdims=True)
            
            # Backpropagation for Actor
            d_act = np.zeros_like(probs)
            d_act[np.arange(N), actions] = -np.clip(advantages, -2.0, 2.0) / N
            d_z_act = probs * (d_act - np.sum(d_act * probs, axis=1, keepdims=True))
            
            dW_actor = np.dot(cache["a_sh"].T, d_z_act)
            db_actor = np.sum(d_z_act, axis=0, keepdims=True)
            
            # Shared backprop
            da_sh = np.dot(d_z_act, self.ac.W_actor.T) + np.dot(d_val, self.ac.W_critic.T)
            dz_sh = da_sh * tanh_derivative(cache["z_sh"])
            
            dW_shared = np.dot(cache["x"].T, dz_sh)
            db_shared = np.sum(dz_sh, axis=0, keepdims=True)
            
            # Updates
            self.ac.W_shared -= self.lr_actor * dW_shared
            self.ac.b_shared -= self.lr_actor * db_shared
            self.ac.W_actor -= self.lr_actor * dW_actor
            self.ac.b_actor -= self.lr_actor * db_actor
            self.ac.W_critic -= self.lr_critic * dW_critic
            self.ac.b_critic -= self.lr_critic * db_critic
            
        # Clear rollout buffers
        self.states.clear()
        self.actions.clear()
        self.log_probs.clear()
        self.rewards.clear()
        self.values.clear()
        self.dones.clear()
        
        return float(policy_loss)

    def save(self, filepath: str):
        with open(filepath, "wb") as f:
            pickle.dump({
                "W_shared": self.ac.W_shared, "b_shared": self.ac.b_shared,
                "W_actor": self.ac.W_actor, "b_actor": self.ac.b_actor,
                "W_critic": self.ac.W_critic, "b_critic": self.ac.b_critic
            }, f)

    def load(self, filepath: str):
        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.ac.W_shared = data["W_shared"]
            self.ac.b_shared = data["b_shared"]
            self.ac.W_actor = data["W_actor"]
            self.ac.b_actor = data["b_actor"]
            self.ac.W_critic = data["W_critic"]
            self.ac.b_critic = data["b_critic"]

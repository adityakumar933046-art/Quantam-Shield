"""
Controlled Attack Simulation Module for Q-SHIELD Security Platform.
Provides isolated, defensive simulation environments to verify platform detection capabilities.
"""

from attack_simulation.base_simulator import BaseSimulator, generate_simulation_id, AttackType, SimulationStatus
from attack_simulation.document_tampering import DocumentTamperingSimulator
from attack_simulation.signature_forgery import SignatureForgerySimulator
from attack_simulation.replay_simulation import ReplayAttackSimulator
from attack_simulation.impersonation import ImpersonationSimulator
from attack_simulation.unauthorized_attempt import UnauthorizedAttemptSimulator
from attack_simulation.signature_manipulation import SignatureManipulationSimulator
from attack_simulation.quantum_channel_simulation import QuantumChannelSimulator
from attack_simulation.results import calculate_simulation_metrics, ResultsAggregator

__all__ = [
    "BaseSimulator",
    "generate_simulation_id",
    "DocumentTamperingSimulator",
    "SignatureForgerySimulator",
    "ReplayAttackSimulator",
    "ImpersonationSimulator",
    "UnauthorizedAttemptSimulator",
    "SignatureManipulationSimulator",
    "QuantumChannelSimulator",
    "calculate_simulation_metrics",
    "ResultsAggregator",
    "AttackType",
    "SimulationStatus",
]


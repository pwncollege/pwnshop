ALL_CHALLENGES = { }
ALL_MODULES = { }
MODULE_LEVELS = { }

from .challenges import Challenge, KernelChallenge, WindowsChallenge, ChallengeGroup, retry
from .register import register_challenge, register_challenges

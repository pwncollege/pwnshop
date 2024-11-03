ALL_CHALLENGES = { }
ALL_MODULES = { }
MODULE_LEVELS = { }

from .challenge import Challenge, KernelChallenge, WindowsChallenge, ChallengeGroup, retry
from .register import register_challenge, register_challenges

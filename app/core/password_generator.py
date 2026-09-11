import secrets
import string
from typing import List, Optional, Set
from pydantic import BaseModel, Field

AMBIGUOUS_CHARS = set("1lI0Oo2Z5S8B")

# Standard wordlist snippet for passphrase mode
PASSPHRASE_WORDS = [
    "correct", "horse", "battery", "staple", "galaxy", "quantum", "shield", "fortress",
    "horizon", "beacon", "titanium", "phoenix", "cascade", "orbit", "prism", "velocity",
    "shadow", "starlight", "vanguard", "solstice", "monolith", "zenith", "nebulous",
    "cipher", "vector", "tesseract", "hyperion", "valiant", "obsidian", "veritas"
]

class PasswordPolicy(BaseModel):
    length: int = Field(default=24, ge=8, le=128)
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = True
    passphrase_mode: bool = False
    word_count: int = 4
    separator: str = "-"
    custom_allowed_symbols: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    disallowed_symbols: str = ""

class PasswordGenerator:
    """
    Cryptographically secure random password generator using Python's secrets module (CSPRNG).
    Never uses predictable seeds, timestamps, or pseudo-randomness.
    """

    def __init__(self):
        self._generated_history: Set[str] = set()

    def generate(self, policy: Optional[PasswordPolicy] = None) -> str:
        policy = policy or PasswordPolicy()

        for _ in range(100):  # Retry loop to guarantee uniqueness and policy constraints
            if policy.passphrase_mode:
                password = self._generate_passphrase(policy)
            else:
                password = self._generate_character_password(policy)

            if password not in self._generated_history:
                self._generated_history.add(password)
                return password

        raise RuntimeError("Failed to generate unique password after multiple attempts.")

    def _generate_passphrase(self, policy: PasswordPolicy) -> str:
        chosen_words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(policy.word_count)]
        if policy.use_uppercase:
            chosen_words = [w.capitalize() for w in chosen_words]
        
        passphrase = policy.separator.join(chosen_words)
        if policy.use_digits:
            passphrase += policy.separator + str(secrets.randbelow(900) + 100)
        if policy.use_symbols:
            passphrase += secrets.choice("!@#$%^&*")
        return passphrase

    def _generate_character_password(self, policy: PasswordPolicy) -> str:
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        symbols = "".join(c for c in policy.custom_allowed_symbols if c not in policy.disallowed_symbols)

        if policy.exclude_ambiguous:
            uppercase = "".join(c for c in uppercase if c not in AMBIGUOUS_CHARS)
            lowercase = "".join(c for c in lowercase if c not in AMBIGUOUS_CHARS)
            digits = "".join(c for c in digits if c not in AMBIGUOUS_CHARS)
            symbols = "".join(c for c in symbols if c not in AMBIGUOUS_CHARS)

        pools: List[str] = []
        guaranteed: List[str] = []

        if policy.use_uppercase and uppercase:
            pools.append(uppercase)
            guaranteed.append(secrets.choice(uppercase))
        if policy.use_lowercase and lowercase:
            pools.append(lowercase)
            guaranteed.append(secrets.choice(lowercase))
        if policy.use_digits and digits:
            pools.append(digits)
            guaranteed.append(secrets.choice(digits))
        if policy.use_symbols and symbols:
            pools.append(symbols)
            guaranteed.append(secrets.choice(symbols))

        if not pools:
            pools = [string.ascii_letters + string.digits]
            guaranteed = [secrets.choice(pools[0])]

        all_chars = "".join(pools)
        remaining_len = max(0, policy.length - len(guaranteed))
        random_chars = [secrets.choice(all_chars) for _ in range(remaining_len)]

        full_list = guaranteed + random_chars
        # Cryptographically secure shuffle using Fisher-Yates with secrets.randbelow
        for i in range(len(full_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            full_list[i], full_list[j] = full_list[j], full_list[i]

        return "".join(full_list)

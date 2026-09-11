import pytest
from app.core.password_generator import PasswordGenerator, PasswordPolicy, AMBIGUOUS_CHARS

def test_password_generator_length_and_uniqueness():
    generator = PasswordGenerator()
    policy = PasswordPolicy(length=32)
    
    passwords = [generator.generate(policy) for _ in range(50)]
    assert len(passwords) == 50
    assert len(set(passwords)) == 50  # 100% unique
    
    for p in passwords:
        assert len(p) == 32

def test_password_generator_ambiguous_exclusion():
    generator = PasswordGenerator()
    policy = PasswordPolicy(length=64, exclude_ambiguous=True)
    
    for _ in range(20):
        p = generator.generate(policy)
        for amb in AMBIGUOUS_CHARS:
            assert amb not in p

def test_passphrase_mode():
    generator = PasswordGenerator()
    policy = PasswordPolicy(passphrase_mode=True, word_count=4, separator="-")
    
    passphrase = generator.generate(policy)
    parts = passphrase.split("-")
    assert len(parts) >= 4

"""Rule registry. Add each new rule class here as KC-02 to KC-11 are implemented."""
from kerbo_s.rules.kc01 import KC01PasswordAge

ALL_RULES = [KC01PasswordAge()]

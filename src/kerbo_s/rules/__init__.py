"""Rule registry. Add each new rule class here as KC-02 to KC-11 are implemented."""
from kerbo_s.rules.kc01 import KC01PasswordAge
from kerbo_s.rules.kc02 import KC02ServicePasswordAge
from kerbo_s.rules.kc03 import KC03WeakPasswordPolicy
from kerbo_s.rules.kc04 import KC04InactiveUser
from kerbo_s.rules.kc06 import KC06UnjustifiedAdmin
from kerbo_s.rules.kc07 import KC07WeakEncryption
from kerbo_s.rules.kc08 import KC08TicketLifetime
from kerbo_s.rules.kc09 import KC09RenewableLifetime

ALL_RULES = [
    KC01PasswordAge(),
    KC02ServicePasswordAge(),
    KC03WeakPasswordPolicy(),
    KC04InactiveUser(),
    KC06UnjustifiedAdmin(),
    KC07WeakEncryption(),
    KC08TicketLifetime(),
    KC09RenewableLifetime(),
]

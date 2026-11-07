from datetime import datetime
from pathlib import Path
from kerbo_s.models import Principal, Policy, Snapshot
from kerbo_s.parsers.kerberos_conf import parse_profile

def classify_principal(name: str) -> str:
    """Classify a Kerberos principal by its name."""
    principal = name.split("@", 1)[0]

    if (
        principal == "K/M"
        or principal.startswith(("krbtgt/", "kadmin/", "kiprop/"))
    ):
        return "internal"

    if principal.endswith("/admin"):
        return "admin"

    if "/" in principal:
        return "service"

    return "user"

def parse_kadmin_line(line: str):
    """Split a Kerberos output line into its label and value."""
    line = line.strip()

    if ": " not in line:
        raise ValueError(f"Invalid Kerberos output line: {line}")

    label, value = line.split(": ", 1)

    if not label or not value.strip():
        raise ValueError(f"Invalid Kerberos output line: {line}")

    return label, value.strip()

def parse_kadmin_date(text):
    """Convert a Kerberos date string into a Python datetime."""
    text = text.strip()

    if text in ("[never]", ""):
        return None

    parts = text.split()

    if len(parts) == 6:
        parts = parts[:4] + parts[5:]

    # Times use the KDC's clock (UTC on our lab VM).
    return datetime.strptime(
        " ".join(parts),
        "%a %b %d %H:%M:%S %Y"
    )

def parse_kadmin_duration(text: str) -> int:
    """Convert a Kerberos duration into whole days."""
    parts = text.strip().split()

    if len(parts) != 3 or parts[1] not in ("day", "days"):
        raise ValueError(f"Invalid Kerberos duration: {text}")

    days = int(parts[0])
    hours, minutes, seconds = map(int, parts[2].split(":"))

    if days < 0 or not (0 <= hours < 24 and 0 <= minutes < 60 and 0 <= seconds < 60):
        raise ValueError(f"Invalid Kerberos duration: {text}")

    return days


def parse_principal(
    text: str,
    errors: list | None = None,
    source: str = "getprinc",
) -> Principal:
    """Parse principal details and record malformed lines."""
    data = {}
    keys = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue

        try:
            label, value = parse_kadmin_line(line)

            if label == "Key":
                parts = value.split(", ", 1)
                if len(parts) != 2:
                    raise ValueError(f"Invalid Key entry: {value}")
                keys.append(parts[1].strip())

            elif label in (
                "Principal",
                "Last password change",
                "Last successful authentication",
                "Policy",
            ):
                data[label] = value

        except ValueError as exc:
            if errors is None:
                raise
            errors.append((source, f"Line {line_number}: {exc}"))

    if not data.get("Principal"):
        raise ValueError("Missing Principal field")

    name = data["Principal"]

    
    def parse_date_field(label):
        value = data.get(label, "[never]")

        try:
            return parse_kadmin_date(value)
        except ValueError as exc:
            if errors is None:
                raise
            errors.append((source, f"{label}: {exc}"))
            return None


    return Principal(
        name=name,
        kind=classify_principal(name),
        last_password_change=parse_date_field(
            "Last password change"
        ),
        last_successful_auth=parse_date_field(
            "Last successful authentication"
        ),
        policy=(
            None
            if data.get("Policy", "[none]") == "[none]"
            else data["Policy"]
        ),
        key_enctypes=tuple(keys),
    )


def parse_policy(
    text: str,
    errors: list | None = None,
    source: str = "getpol",
) -> Policy:
    """Parse policy details and record malformed lines."""
    data = {}

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue

        try:
            label, value = parse_kadmin_line(line)
            data[label] = value

        except ValueError as exc:
            if errors is None:
                raise
            errors.append((source, f"Line {line_number}: {exc}"))

    if not data.get("Policy"):
        raise ValueError("Missing Policy field")

    def parse_field(label, converter):
        if label not in data:
            return None
        try:
            return converter(data[label])
        except ValueError as exc:
            if errors is None:
                raise
            errors.append((source, f"{label}: {exc}"))
            return None

    return Policy(
        name=data["Policy"],
        min_length=parse_field("Minimum password length", int),
        max_life_days=parse_field(
            "Maximum password life", parse_kadmin_duration
        ),
        min_life_days=parse_field(
            "Minimum password life", parse_kadmin_duration
        ),
        history=parse_field("Number of old keys kept", int),
        max_failures=parse_field(
            "Maximum password failures before lockout", int
        ),
    )


def load_fixture_dir(path) -> Snapshot:
    """Load Kerberos principal and policy files into a Snapshot."""
    folder = Path(path)

    if not folder.is_dir():
        raise FileNotFoundError(f"Fixture folder not found: {folder}")

    timestamp_file = folder / "collected_at.txt"

    if not timestamp_file.is_file():
        raise FileNotFoundError(f"Missing collected_at.txt: {folder}")

    collected_at = datetime.fromisoformat(
        timestamp_file.read_text(encoding="utf-8").strip()
    )

    snapshot = Snapshot(collected_at=collected_at)

    def read_file(filename):
        file_path = folder / filename
        try:
            return file_path.read_text(encoding="utf-8")
        except OSError as exc:
            snapshot.errors.append((filename, str(exc)))
            return None

    # Load principal names and their detail files.
    principal_list = read_file("listprincs.txt")

    if principal_list is not None:
        for name in principal_list.splitlines():
            name = name.strip()
            if not name:
                continue

            filename = f"getprinc_{name.replace('/', '_')}.txt"
            content = read_file(filename)

            if content is None:
                continue

            try:
                principal = parse_principal(
                    content, snapshot.errors, filename
                )
                snapshot.principals.append(principal)
            except ValueError as exc:
                snapshot.errors.append((filename, str(exc)))

    # Load policy names and their detail files.
    policy_list = read_file("getpols.txt")

    if policy_list is not None:
        for name in policy_list.splitlines():
            name = name.strip()
            if not name:
                continue

            filename = f"getpol_{name}.txt"
            content = read_file(filename)

            if content is None:
                continue

            try:
                policy = parse_policy(
                    content, snapshot.errors, filename
                )
                snapshot.policies.append(policy)
            except ValueError as exc:
                snapshot.errors.append((filename, str(exc)))

    # Load the Kerberos config files with parse_profile (S2-09, FR-COL-03).
    for filename in ("krb5.conf", "kdc.conf"):
        content = read_file(filename)

        if content is None:
            continue

        settings, errors = parse_profile(content, filename)
        snapshot.config.extend(settings)
        snapshot.errors.extend(errors)

    return snapshot


import json
from typing import Protocol



class Provider(Protocol):
    def complete(self, prompt: str) -> str:
        ...



class ProviderUnavailable(RuntimeError):
    """Raised when a provider cannot complete a request."""



class MockProvider:
    def complete(self, prompt: str) -> str:
        return json.dumps(
            {
                "explanation": "An audit rule flagged a policy deviation.",
                "risk_context": "Review the finding to assess its operational impact.",
                "remediation": [
                    "Compare the observed value with the expected threshold.",
                    "Review the finding with the Kerberos administrator.",
                ],
            }
        )

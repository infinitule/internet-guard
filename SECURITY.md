# Security status

Version 0.1.0 is experimental. No independent security audit, production uptime
assessment, sustained-load certification, or life-critical suitability assessment
has been performed. It is a local DNS filtering component, not a security boundary
against an adversary who controls the host or can choose another network path.

For a security report, use a private vulnerability report if the repository owner
has enabled that GitHub feature. Otherwise request a private reporting channel
from the owner without posting exploit details, credentials, or user DNS logs
publicly. There is no staffed incident-response or remediation SLA.

Useful review areas include parser resource consumption, service-binding address
hints, unusual IP encodings, response/request correlation, policy precedence,
policy reload failures, log privacy, TLS validation, and concurrency limits.

The default upstream sees queried names and the deployment's source address.
Local audit tokens deliberately cannot be decoded with a stored key: the HMAC key
exists only in process memory and rotates on restart. Logs are pseudonymous,
not anonymous; timing, type, and repeated tokens can still reveal patterns.

No inbound TLS interception, network scanning, exploitation, persistence,
credential collection, or autonomous remediation is implemented. Deploy only
where the operator controls the resolver configuration and can assess outages.

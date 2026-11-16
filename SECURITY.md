# Security policy

dotvpn is beta software used in hostile network environments. Please report vulnerabilities privately.

## Reporting

Use GitHub private vulnerability reporting: <https://github.com/payam-foundation/dotvpn-dnstest/security/advisories/new>.

Do not open a public issue for a vulnerability. Include the affected version, a reproduction, and the impact you expect. We aim to acknowledge reports within 72 hours.

## Supported versions

Only the latest git tag of this repository receives security fixes. Older tags are unsupported. 

## Scope

In scope: the leak test server never answering outside its zone (open resolver), results readable by anyone but the visitor who asked for them, any record of a visitor beyond the 60 second in-memory result, and the update path (a bad image or ASN table taking the service down or being installed unverified).

Out of scope: denial of service by volume against a single small VPS, and resolver or ASN data that is wrong because the upstream iptoasn.com table is wrong.

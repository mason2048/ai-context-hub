# Security policy

## Supported versions

AI Context Hub `0.1.x` is a source preview. Security fixes are made on the default branch; there is no hosted service or production support commitment.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability, secret exposure, path disclosure, local-service bypass, unsafe import/export, or dependency compromise.

Use the repository **Security** tab and select **Report a vulnerability** to open a GitHub Private Vulnerability Report:

<https://github.com/mason2048/ai-context-hub/security/advisories/new>

Include the affected revision, operating system and Node version, reproduction steps, impact, and a minimal redacted proof of concept. Never include real credentials, private repository content, signing keys, or user data. You should receive an initial acknowledgement within seven days. Disclosure timing will be coordinated after the issue is understood and a fix is available.

## Security boundary

The application is intended for a trusted local machine and binds to loopback. Scanned and imported content remains untrusted text and is never executed. Pattern-based secret detection can miss or misclassify values; immediately revoke and rotate any real credential that may have been exposed.

## Dependency reports

For a dependency advisory without a demonstrated product impact, use GitHub's advisory references. For an exploitable path in AI Context Hub, use Private Vulnerability Reporting.

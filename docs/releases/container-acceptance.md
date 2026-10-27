# Container distribution acceptance

This page records the current public distribution boundary. The release-specific record is [v0.1.0-rc.1 evidence](v0.1.0-evidence.md); the required release contract is in the [container policy](container-policy.md). Private build logs and local verification receipts are not published here.

## v0.1.0-rc.1

- Image source revision: `320e3e1e4e8e6ffcf5886f15b45e50388a66391c`.
- OCI index digest: `sha256:b808603d6050b2473bc119755a78785c220b48c515a0acba55c2614d385bab94`.
- Docker Hub and GHCR both returned this digest for the release tag. Isolated-config anonymous digest pulls and ready-endpoint smoke checks passed for both registries on 2026-10-27.
- The GHCR package is public and its GitHub Packages API record identifies `JasonTM17/Uptime-Monitoring-Platform` as the linked repository.
- Hosted application deployment: **NOT_RUN**.

The existing image, tag, and digest were retained when the package association was completed.

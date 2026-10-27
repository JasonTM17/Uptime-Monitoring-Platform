# Container distribution acceptance

This page records the current public distribution boundary. The release-specific record is [v0.1.0-rc.1 evidence](v0.1.0-evidence.md); the required release contract is in the [container policy](container-policy.md). Private build logs and local verification receipts are not published here.

## v0.1.0-rc.1

- Image source revision: `320e3e1e4e8e6ffcf5886f15b45e50388a66391c`.
- OCI index digest: `sha256:b808603d6050b2473bc119755a78785c220b48c515a0acba55c2614d385bab94`.
- Docker Hub and GHCR both returned this digest for the release tag in an unauthenticated manifest read and isolated-config anonymous digest pulls on 2026-10-26. Previously recorded ready-endpoint smoke checks passed for both registries.
- The GHCR package is public, but its GitHub Packages API record still has no repository association. The image remains anonymously available; the association criterion is still open.
- Hosted application deployment: **NOT_RUN**.

Do not change the existing image, tag, or digest to complete the package association. Verify the package setting and registry readback before changing this record.

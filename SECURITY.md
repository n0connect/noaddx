# Security Policy

noaddx. exists to protect people who need it to; security reports are the most valuable
contribution this project can receive.

## Reporting a Vulnerability

- Report privately through GitHub: **Security → Report a vulnerability** on this repository.
- Do **not** open a public issue, pull request or discussion for anything exploitable.
- Include what an attacker needs (position, access, interaction), the impact, and the smallest
  reproduction you have. A failing test against the real system is ideal.

You will get an acknowledgement as soon as the report is read, an assessment, and credit in the
changelog if you want it. Please allow a fix to ship before publishing details.

## Supported Versions

Only the latest commit on `main` is supported. noaddx. is pre-release (`1.0-dev`): stored data
formats and protocol labels may change, and fixes are not backported.

## Scope

In scope: the backend (`backend/`), the browser client (`frontend/`), the protocol described in
[`docs/security/cryptography.md`](docs/security/cryptography.md), and the deployment files
(`docker-compose*.yaml`, `*.Dockerfile`, `nginx*.conf`, `tor/torrc`, `Makefile`).

Out of scope, because they are stated design limits
([`docs/security/threat-model.md`](docs/security/threat-model.md#known-limitations)):
the absence of forward secrecy, an operator who serves modified JavaScript, an operator holding
the master key learning who talks to whom, and network-level metadata seen by the server.

## How Fixes Are Made

Every security fix lands with a test that drives the real system and fails without the fix,
and is listed under **Security** in [`CHANGELOG.md`](CHANGELOG.md).

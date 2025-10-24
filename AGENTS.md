# Repository Guidelines

## Project Structure & Module Organization
- `main.py` dispatches between the Ghost Comm simulation and the standalone C2 server.
- `ghost_comm_lib/` hosts reusable client, network, crypto, and node packages—favor extending these modules.
- `Ghost_Comm/src/` is the Tor-enabled integration harness; keep long-running orchestration scripts here.
- `botnet/` contains legacy prototypes and GUI artefacts; touch only when stabilising backwards compatibility.
- Blockchain pieces (`C2UrlRegistry.sol`, `contract_meta.json`) back the registry logic in `blockchain_utils.py`.

## Build, Test, and Development Commands
- Create a virtualenv (`python -m venv .venv && source .venv/bin/activate`) and install deps via `pip install -r requirements.txt`.
- Boot the Ghost Comm demo with `python main.py ghost_comm`; it spins up a primary node and sample client.
- Run the command-and-control server alone through `python start_c2.py`, which wraps the `c2.py` entrypoint.
- Redeploy and record registry details with `python blockchain_utils.py` once Ganache or eth-tester is reachable.

## Coding Style & Naming Conventions
- Adopt PEP 8: 4-space indents, ≤100 character lines, and concise docstrings on public functions.
- Stick to snake_case for modules and functions, PascalCase for classes, and SCREAMING_SNAKE_CASE for constants.
- Use explicit package imports (`from ghost_comm_lib.crypto.keys import KeyManager`) to signal ownership and dependencies.

## Testing Guidelines
- Mirror library paths under `ghost_comm_lib/tests` (e.g., `client/test_client.py`) for unit coverage.
- Gate Tor-heavy scenarios behind markers in `Ghost_Comm/tests` so they can be skipped in CI.
- Install dev tooling with `pip install pytest pytest-mock` and execute suites via `pytest -q`.
- Mock outbound network and blockchain calls to keep runs deterministic; target ≥80% coverage on new modules.

## Commit & Pull Request Guidelines
- Replace “Auto backup …” messages with imperative subjects such as “Document Ghost_Comm bootstrap”.
- Reference tickets with `Refs #123` and squash fix-up commits before requesting review.
- PRs should state purpose, testing evidence, and operational impact; attach screenshots for GUI-facing changes.
- Secure one reviewer for Python-only updates and two for Tor or smart-contract modifications; verify local `pytest` and `python main.py ghost_comm` first.

## Security & Configuration Tips
- Never commit `.onion` endpoints, Tor credentials, or private keys; store secrets in ignored `.env.local` files.
- Ensure a Tor service exposes SOCKS 9050 and control 9051 before running integration demos.
- When sharing logs, redact client identifiers and contract addresses; redeploy via `python blockchain_utils.py` after public demos.

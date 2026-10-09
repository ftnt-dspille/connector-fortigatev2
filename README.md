# FortiGate v2 Connector

The full connector documentation is the README that ships inside the connector package:

**→ [`fortigatev2/README.md`](fortigatev2/README.md)**

Manages a FortiGate firewall from FortiSOAR playbooks over the FortiOS REST API. Forked
from Fortinet's `fortigate-firewall` 5.4.0 connector, with the bugs found by live testing
against FortiOS 7.6 fixed; it installs alongside `fortigate-firewall`.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest          # offline suite: FortiOS mocked, no appliance needed
.venv/bin/ruff check
.venv/bin/mypy fortigatev2
```

Tests stub FortiSOAR's appliance-only runtime packages (see `tests/conftest.py`).

### Live tests

`tests/test_live.py` runs every operation against a real FortiGate: create → read →
update → delete for each object type, each write read back independently over plain
REST. Everything it creates is named `fsrtest-<run>-*` or uses RFC 5737 / RFC 3849
documentation addresses, firewall policies are created **disabled** at IDs 9900+, and
the block profiles are fresh test profiles no policy uses, so a run never changes what
traffic the FortiGate passes. All test objects are purged before and after the session.

Put the target in a gitignored `.env.live` at the repo root:

```bash
FGT_HOST=fortigate.example.com
FGT_PORT=443
FGT_API_KEY=<rest-api-admin-key>
FGT_VDOM=root
FGT_VERIFY_SSL=false
# optional, for execute_command
FGT_SSH_USER=admin
FGT_SSH_PASSWORD=<your-password>
FGT_SSH_PORT=22
```

```bash
.venv/bin/pytest --live
```

## Releasing

Bump `version` in `fortigatev2/info.json`, add the notes to `fortigatev2/release_notes.md`,
then push a matching `v*.*.*` tag. CI builds `connector-fortigatev2-<version>.tgz` from the
`fortigatev2/` directory and attaches it to a GitHub release.

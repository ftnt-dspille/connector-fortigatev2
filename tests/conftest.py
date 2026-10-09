"""Shared pytest setup for the fortigatev2 connector.

* Installs minimal ``connectors.*`` stubs so the connector imports without the
  FortiSOAR runtime.
* ``live_config`` / ``fgt`` fixtures for the live suite, read from the
  gitignored ``.env.live`` next to this package (or the process env).
  Live tests are skipped unless ``--live`` is passed.
"""
import logging
import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _install_runtime_stubs():
    if 'connectors.core.connector' in sys.modules:
        return
    for name in ('connectors', 'connectors.core', 'connectors.cyops_utilities'):
        mod = types.ModuleType(name)
        mod.__path__ = []
        sys.modules[name] = mod

    core = types.ModuleType('connectors.core.connector')

    class ConnectorError(Exception):
        pass

    class Connector:
        pass

    core.ConnectorError = ConnectorError
    core.Connector = Connector
    core.get_logger = logging.getLogger
    sys.modules['connectors.core.connector'] = core

    builtins_mod = types.ModuleType('connectors.cyops_utilities.builtins')

    def download_file_from_cyops(iri, *args, **kwargs):
        raise NotImplementedError('download_file_from_cyops is not available outside FortiSOAR')

    builtins_mod.download_file_from_cyops = download_file_from_cyops
    sys.modules['connectors.cyops_utilities.builtins'] = builtins_mod


_install_runtime_stubs()


def pytest_addoption(parser):
    parser.addoption('--live', action='store_true', default=False,
                     help='run tests against the live FortiGate in .env.live')


def pytest_configure(config):
    config.addinivalue_line('markers', 'live: needs a reachable FortiGate (run with --live)')


def pytest_collection_modifyitems(config, items):
    if config.getoption('--live'):
        return
    skip = pytest.mark.skip(reason='live test; pass --live')
    for item in items:
        if 'live' in item.keywords:
            item.add_marker(skip)


def load_env(path=ROOT / '.env.live'):
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, value = line.partition('=')
                env[key.strip()] = value.strip()
    env.update({k: v for k, v in os.environ.items() if k.startswith(('FGT_', 'FSR_'))})
    return env


@pytest.fixture(scope='session')
def env():
    values = load_env()
    if not values.get('FGT_HOST') or not values.get('FGT_API_KEY'):
        pytest.skip('FGT_HOST / FGT_API_KEY not set (.env.live)')
    return values


@pytest.fixture(scope='session')
def live_config(env):
    """Connector configuration dict, shaped exactly like the FortiSOAR config form."""
    return {
        'address': 'https://{}'.format(env['FGT_HOST']),
        'port': int(env.get('FGT_PORT', 443)),
        'api_key': env['FGT_API_KEY'],
        'vdom': env.get('FGT_VDOM', 'root'),
        'verify_ssl': env.get('FGT_VERIFY_SSL', 'false').lower() == 'true',
        'url_block_policy': '',
        'app_block_policy': '',
    }


@pytest.fixture(scope='session')
def fgt(live_config):
    from tests.fgt_rest import FortiGateRest
    return FortiGateRest(live_config)

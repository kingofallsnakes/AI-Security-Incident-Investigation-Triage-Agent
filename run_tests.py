"""Test runner that disables third-party entrypoint autoloading.

Prevents Windows Application Control / AppLocker from blocking unused C-extensions
(such as uuid_utils / langsmith) during pytest entrypoint scanning.
"""
import os
import sys

os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

import pytest

if __name__ == "__main__":
    args = sys.argv[1:] if len(sys.argv) > 1 else ["tests", "-v"]
    sys.exit(pytest.main(args))


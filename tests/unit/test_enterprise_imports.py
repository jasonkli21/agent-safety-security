"""Default CLI and protected runtime stay functional without enterprise dependencies."""

import subprocess
import sys


def test_default_imports_and_runtime_without_optional_dependencies():
    code = """
import importlib.abc
import sys
import runpy
class AbsentOptional(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        absent = {'cryptography', 'jwt', 'starlette', 'uvicorn', 'mcp', 'langchain_core'}
        if fullname.split('.')[0] in absent:
            raise ModuleNotFoundError(fullname)
sys.meta_path.insert(0, AbsentOptional())
import agentsec.cli.main
import agentsec.enterprise.service
runpy.run_path('examples/multi_agent/local_session.py', run_name='__main__')
"""
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    assert "PASS: two-hop read" in result.stdout

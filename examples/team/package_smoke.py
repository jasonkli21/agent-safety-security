"""Inspect built archives and run protected runtime from wheel or unpacked sdist, offline."""

import importlib.abc
import runpy
import sys
import tarfile
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

artifacts = Path(sys.argv[1])
wheel = next(artifacts.glob("*.whl"))
source = next(artifacts.glob("*.tar.gz"))
with zipfile.ZipFile(wheel) as archive:
    assert "agentsec/enterprise/federation.py" in archive.namelist()
with tarfile.open(source) as archive:
    assert any(p.endswith("/src/agentsec/enterprise/federation.py") for p in archive.getnames())

unpacked = TemporaryDirectory(prefix="agentsec-sdist-smoke-")
if "--sdist" in sys.argv:
    with tarfile.open(source) as archive:
        archive.extractall(unpacked.name, filter="data")
    package_root = next(Path(unpacked.name).glob("*/src"))
    sys.path.insert(0, str(package_root))
else:
    sys.path.insert(0, str(wheel))
if "--without-extras" in sys.argv:

    class NoOptional(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in {
                "cryptography",
                "jwt",
                "starlette",
                "uvicorn",
                "mcp",
                "langchain_core",
            }:
                raise ModuleNotFoundError(fullname)

    sys.meta_path.insert(0, NoOptional())
agentsec = importlib.import_module("agentsec")
importlib.import_module("agentsec.cli.main")
importlib.import_module("agentsec.enterprise.service")

assert agentsec.__file__ is not None
assert (unpacked.name if "--sdist" in sys.argv else ".whl/") in agentsec.__file__
runpy.run_path("examples/multi_agent/local_session.py", run_name="__main__")
print(
    "PACKAGED_IMPORT_OK",
    "SDIST" if "--sdist" in sys.argv else "WHEEL",
    "WITHOUT_OPTIONAL" if "--without-extras" in sys.argv else "WITH_OPTIONAL",
)
unpacked.cleanup()

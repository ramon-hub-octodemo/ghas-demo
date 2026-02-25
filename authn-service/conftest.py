"""pytest conftest: load 'authn-service.py' (hyphen in name) as 'authn_service'."""
import importlib.util
import os
import sys

# Set env vars before loading the module so Flask app initialises cleanly
os.environ.setdefault("CLIENT_ID", "test_client_id")
os.environ.setdefault("CLIENT_SECRET", "test_client_secret")

_service_path = os.path.join(os.path.dirname(__file__), "authn-service.py")
_spec = importlib.util.spec_from_file_location("authn_service", _service_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["authn_service"] = _mod
_spec.loader.exec_module(_mod)

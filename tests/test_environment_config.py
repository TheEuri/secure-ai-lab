import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dotenv import load_dotenv


class EnvironmentConfigurationTests(unittest.TestCase):
    def test_bootstrap_loads_repository_dotenv_before_environment_configuration(self):
        source = Path("run.py").read_text(encoding="utf-8")
        load_call = 'load_dotenv(dotenv_path=BASE_DIR / ".env", override=False)'

        self.assertIn(load_call, source)
        self.assertLess(source.index(load_call), source.index("TRANSPORT_DEFAULTS"))
        self.assertIn("python-dotenv==1.2.1", Path("requirements.txt").read_text())

    def test_repository_style_dotenv_load_preserves_exported_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dotenv_path = Path(temp_dir) / ".env"
            dotenv_path.write_text(
                "AI_PROVIDER=from-file\n"
                "GEMINI_MODEL=fictional-model-from-file\n"
                "AI_TIMEOUT_SECONDS=9\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"AI_PROVIDER": "already-exported"},
                clear=False,
            ):
                for name in ("GEMINI_MODEL", "AI_TIMEOUT_SECONDS"):
                    os.environ.pop(name, None)
                loaded = load_dotenv(dotenv_path=dotenv_path, override=False)

                self.assertTrue(loaded)
                self.assertEqual(os.environ["AI_PROVIDER"], "already-exported")
                self.assertEqual(
                    os.environ["GEMINI_MODEL"], "fictional-model-from-file"
                )
                self.assertEqual(os.environ["AI_TIMEOUT_SECONDS"], "9")


if __name__ == "__main__":
    unittest.main()

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "honeypot-web" / "fastapi_app.py"


class DashboardStatsTests(unittest.TestCase):
    def test_top_ips_and_countries(self):
        spec = importlib.util.spec_from_file_location("fastapi_app_test", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader
        spec.loader.exec_module(module)
        stats = module.compute_stats(
            [
                {"ip": "1.1.1.1", "country": "AU", "timestamp": "2026-08-02T12:00:00Z"},
                {"ip": "1.1.1.1", "country": "AU", "timestamp": "2026-08-02T11:00:00Z"},
                {"ip": "8.8.8.8", "country": "US", "timestamp": "2026-08-02T10:00:00Z"},
            ]
        )
        self.assertEqual(stats["total_attacks"], 3)
        self.assertEqual(stats["unique_ip_count"], 2)
        self.assertEqual(stats["top_ips"][0], {"ip": "1.1.1.1", "count": 2})
        self.assertEqual(stats["top_countries"][0], {"country": "AU", "count": 2})


if __name__ == "__main__":
    unittest.main()

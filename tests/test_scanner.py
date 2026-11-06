import unittest
from src.scanner import HIGH_RISK_PORTS, probe_port


class TestPortScanner(unittest.TestCase):

    def test_high_risk_ports_mapping(self):
        self.assertIn(21, HIGH_RISK_PORTS)
        self.assertIn(80, HIGH_RISK_PORTS)
        self.assertEqual(HIGH_RISK_PORTS[23], "Telnet (Unencrypted Remote Management)")

    def test_probe_closed_port(self):
        # Localhost port 59999 should normally be closed
        result = probe_port("127.0.0.1", 59999, timeout=0.2)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
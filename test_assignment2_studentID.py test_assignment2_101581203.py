import unittest
from assignment2_studentID import PortScanner, common_ports


class TestPortScanner(unittest.TestCase):

    def test_scanner_initialization(self):
        """Test that PortScanner initializes with correct target and empty scan_results."""
        scanner = PortScanner("127.0.0.1")
        self.assertEqual(scanner.target, "127.0.0.1")
        self.assertEqual(scanner.scan_results, [])

    def test_get_open_ports_filters_correctly(self):
        """Test that get_open_ports returns only open port tuples."""
        scanner = PortScanner("127.0.0.1")
        scanner.scan_results.append((22, "Open", "SSH"))
        scanner.scan_results.append((23, "Closed", "Telnet"))
        scanner.scan_results.append((80, "Open", "HTTP"))
        result = scanner.get_open_ports()
        self.assertEqual(len(result), 2)

    def test_common_ports_dict(self):
        """Test that common_ports dictionary has correct mappings."""
        self.assertEqual(common_ports[80], "HTTP")
        self.assertEqual(common_ports[22], "SSH")

    def test_invalid_target(self):
        """Test that setting an empty target is rejected by the setter."""
        scanner = PortScanner("127.0.0.1")
        scanner.target = ""
        self.assertEqual(scanner.target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
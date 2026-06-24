import unittest
from simulator.attack_catalog import load_catalog, get_by_label
from simulator.sampler import sample_row


# pathlib.Path not needed here


class TestSimulator(unittest.TestCase):
    def test_catalog_load(self):
        rows = load_catalog()
        self.assertTrue(len(rows) > 0)

    def test_get_by_label(self):
        rows = load_catalog()
        ex = get_by_label(rows, 'Exploits')
        self.assertTrue(len(ex) >= 1)

    def test_sampler(self):
        rows = load_catalog()
        tmpl = rows[0]
        row = sample_row(tmpl, '10.1.1.X')
        self.assertIn('srcip', row)
        self.assertTrue(str(row['srcip']).startswith('10.1.1.'))


if __name__ == '__main__':
    unittest.main()

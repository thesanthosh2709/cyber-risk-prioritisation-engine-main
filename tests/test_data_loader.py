import os
import sys
import unittest
import pandas as pd
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.data_loader import load_vulnerabilities, load_gold_set, load_profiles, run_data_quality_report, DataValidationError, FileMissingError

class TestDataLoader(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.vuln_path = 'data/vulnerabilities.csv'
        cls.gold_path = 'data/gold_set.csv'
        cls.prof_path = 'data/profiles.json'
        
        # Check original file modification times
        cls.orig_mtimes = {
            cls.vuln_path: os.path.getmtime(cls.vuln_path),
            cls.gold_path: os.path.getmtime(cls.gold_path),
            cls.prof_path: os.path.getmtime(cls.prof_path)
        }
        
    def test_01_vulnerabilities_loads_successfully(self):
        df = load_vulnerabilities(self.vuln_path)
        self.assertEqual(len(df), 540)
        self.assertIn('cve_id', df.columns)
        
    def test_02_profiles_loads_successfully(self):
        data = load_profiles(self.prof_path)
        self.assertIn('organizations', data)
        self.assertEqual(len(data['organizations']), 3)
        
    def test_03_gold_set_loads_successfully(self):
        df = load_gold_set(self.gold_path)
        self.assertEqual(len(df), 5)
        self.assertIn('practitioner_rank_bank', df.columns)
        
    def test_04_required_columns_exist(self):
        # Already checked implicitly in load functions, let's explicitly trigger error
        with self.assertRaises(DataValidationError):
            # Create a temp invalid file
            temp_path = 'data/temp_invalid.csv'
            pd.DataFrame({'a': [1,2,3]}).to_csv(temp_path, index=False)
            try:
                load_vulnerabilities(temp_path)
            finally:
                os.remove(temp_path)
                
    def test_05_cvss_values_are_numeric(self):
        df = load_vulnerabilities(self.vuln_path)
        self.assertTrue(pd.api.types.is_numeric_dtype(df['cvss_base_score']))
        
    def test_06_epss_values_are_numeric(self):
        df = load_vulnerabilities(self.vuln_path)
        self.assertTrue(pd.api.types.is_numeric_dtype(df['first_epss']))
        
    def test_07_cisa_kev_is_converted_safely(self):
        df = load_vulnerabilities(self.vuln_path)
        self.assertTrue(pd.api.types.is_bool_dtype(df['cisa_kev']))
        
    def test_08_profiles_contain_expected_fields(self):
        data = load_profiles(self.prof_path)
        org = data['organizations'][0]
        self.assertIn('org_id', org)
        self.assertIn('name', org)
        self.assertIn('sector', org)
        self.assertIn('risk_appetite', org)
        self.assertIn('critical_products', org)
        self.assertIn('weight_modifiers', org)
        
    def test_09_gold_set_mismatch_detected(self):
        vuln_df = load_vulnerabilities(self.vuln_path)
        gold_df = load_gold_set(self.gold_path)
        profiles = load_profiles(self.prof_path)
        
        report = run_data_quality_report(vuln_df, gold_df, profiles)
        self.assertEqual(report['gold_row_count'], 5)
        self.assertEqual(report['gold_cves_in_vuln'], 0)
        
    def test_10_original_files_not_modified(self):
        for path, orig_mtime in self.orig_mtimes.items():
            self.assertEqual(os.path.getmtime(path), orig_mtime, f"{path} was modified!")

if __name__ == '__main__':
    unittest.main(verbosity=2)

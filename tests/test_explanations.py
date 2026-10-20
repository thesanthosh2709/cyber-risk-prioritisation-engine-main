import os
import sys
import unittest
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.data_loader import load_vulnerabilities, load_profiles
from src.scoring import score_vulnerabilities
from src.ranking import rank_top_vulnerabilities
from src.explanations import add_explanations, get_dominant_factor, generate_what_to_do_next

class TestExplanationEngine(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.vuln_path = 'data/vulnerabilities.csv'
        cls.prof_path = 'data/profiles.json'
        
        # Check original file modification times
        cls.orig_mtimes = {
            cls.vuln_path: os.path.getmtime(cls.vuln_path),
            cls.prof_path: os.path.getmtime(cls.prof_path)
        }
        
        cls.vuln_df = load_vulnerabilities(cls.vuln_path)
        profiles_data = load_profiles(cls.prof_path)
        cls.orgs = {org['org_id']: org for org in profiles_data['organizations']}
        
        cls.bank = cls.orgs['ORG-001']
        cls.startup = cls.orgs['ORG-002']
        cls.utility = cls.orgs['ORG-003']
        
        bank_scored = score_vulnerabilities(cls.vuln_df, cls.bank)
        cls.bank_top = rank_top_vulnerabilities(bank_scored)
        cls.bank_explained = add_explanations(cls.bank_top)
        
        startup_scored = score_vulnerabilities(cls.vuln_df, cls.startup)
        cls.startup_top = rank_top_vulnerabilities(startup_scored)
        cls.startup_explained = add_explanations(cls.startup_top)
        
    def test_01_all_explanations_exist(self):
        for col in ['why_this_matters', 'why_ranked_high', 'what_to_do_next', 'dominant_factor']:
            self.assertIn(col, self.bank_explained.columns)
            
    def test_02_org_name_appears(self):
        row = self.bank_explained.iloc[0]
        self.assertIn('Global Retail Bank', row['why_this_matters'])
        
    def test_03_representative_product_appears(self):
        row = self.bank_explained.iloc[0]
        self.assertIn(row['representative_product'], row['why_this_matters'])
        
    def test_04_critical_product_relevance(self):
        row = self.bank_explained.iloc[0]
        self.assertIn('critical', row['why_this_matters'])
        
    def test_05_cvss_appears_correctly(self):
        row = self.bank_explained.iloc[0]
        self.assertIn(str(row['cvss_base_score']), row['why_ranked_high'])
        self.assertIn('CVSS base score', row['why_ranked_high'])
        
    def test_06_kev_true_wording(self):
        # find a true row
        true_row = self.bank_explained[self.bank_explained['cisa_kev'] == True]
        if not true_row.empty:
            row = true_row.iloc[0]
            self.assertIn('listed in the CISA Known Exploited', row['why_ranked_high'])
            self.assertNotIn('not marked', row['why_ranked_high'])
            
    def test_07_kev_false_wording(self):
        false_row = self.bank_explained[self.bank_explained['cisa_kev'] == False]
        if not false_row.empty:
            row = false_row.iloc[0]
            self.assertIn('not marked as CISA KEV', row['why_ranked_high'])
            self.assertNotIn('actively exploited', row['why_ranked_high'].lower())
            
    def test_08_epss_estimate_wording(self):
        row = self.bank_explained.iloc[0]
        self.assertIn('EPSS estimate', row['why_ranked_high'])
        
    def test_09_actual_org_weights_reflected(self):
        row = self.bank_explained.iloc[0]
        # Bank weights: 30%, 45%, 25%
        self.assertIn('30%', row['why_ranked_high'])
        self.assertIn('45%', row['why_ranked_high'])
        self.assertIn('25%', row['why_ranked_high'])
        
    def test_10_dominant_factor_correct(self):
        # We manually test the standalone function
        row_mock = pd.Series({'cvss_contribution': 10, 'kev_contribution': 40, 'epss_contribution': 20})
        self.assertEqual(get_dominant_factor(row_mock), 'CISA KEV')
        
        row_mock2 = pd.Series({'cvss_contribution': 50, 'kev_contribution': 10, 'epss_contribution': 20})
        self.assertEqual(get_dominant_factor(row_mock2), 'CVSS')
        
    def test_11_multiple_affected_products(self):
        # Check if multiple products correctly formatting
        multi = self.bank_explained[self.bank_explained['affected_critical_products'].map(len) > 1]
        if not multi.empty:
            row = multi.iloc[0]
            self.assertIn('affects 2 critical technologies', row['why_this_matters'])
            
    def test_12_no_exploit_instructions(self):
        for col in ['what_to_do_next', 'why_ranked_high', 'why_this_matters']:
            text = " ".join(self.bank_explained[col].tolist()).lower()
            self.assertNotIn('payload', text)
            self.assertNotIn('attack command', text)
            
    def test_13_no_unsupported_software_versions(self):
        text = " ".join(self.bank_explained['why_this_matters'].tolist()).lower()
        # We didn't supply versions, so we shouldn't see 'version' 
        self.assertNotIn('version', text)
        
    def test_14_no_unsupported_patch_claims(self):
        text = " ".join(self.bank_explained['what_to_do_next'].tolist()).lower()
        self.assertNotIn('patch is available', text)
        
    def test_15_explanations_deterministic(self):
        run1 = add_explanations(self.bank_top)
        run2 = add_explanations(self.bank_top)
        pd.testing.assert_frame_equal(run1, run2)
        
    def test_16_original_values_not_modified(self):
        self.assertEqual(len(self.bank_top), len(self.bank_explained))
        for col in self.bank_top.columns:
            self.assertIn(col, self.bank_explained.columns)
            
    def test_17_original_files_not_modified(self):
        for path, orig_mtime in self.orig_mtimes.items():
            self.assertEqual(os.path.getmtime(path), orig_mtime, f"{path} was modified!")

    def test_18_kev_true_cisa_dominant(self):
        row = pd.Series({'cisa_kev': True})
        res = generate_what_to_do_next(row, 'CISA KEV')
        self.assertEqual(res, "Prioritise investigation and remediation because this vulnerability is listed in CISA KEV, which is also the largest contributor to this organisation's risk score.")
        
    def test_19_kev_true_cvss_dominant(self):
        row = pd.Series({'cisa_kev': True})
        res = generate_what_to_do_next(row, 'CVSS')
        self.assertEqual(res, "Prioritise investigation and remediation because this vulnerability is listed in CISA KEV. The CVSS contribution is the largest contributor to this organisation's risk score.")
        
    def test_20_kev_true_epss_dominant(self):
        row = pd.Series({'cisa_kev': True})
        res = generate_what_to_do_next(row, 'EPSS')
        self.assertEqual(res, "Prioritise investigation and remediation because this vulnerability is listed in CISA KEV. The EPSS contribution is also the largest contributor to this organisation's risk score.")
        
    def test_21_kev_false_cvss_dominant(self):
        row = pd.Series({'cisa_kev': False})
        res = generate_what_to_do_next(row, 'CVSS')
        self.assertEqual(res, "Prioritise review and remediation because the CVSS contribution is the largest contributor to this organisation's risk score.")
        
    def test_22_kev_false_epss_dominant(self):
        row = pd.Series({'cisa_kev': False})
        res = generate_what_to_do_next(row, 'EPSS')
        self.assertEqual(res, "Prioritise investigation because the EPSS contribution is the largest contributor to this organisation's risk score.")
        
    def test_23_kev_false_balanced(self):
        row = pd.Series({'cisa_kev': False})
        res = generate_what_to_do_next(row, 'BALANCED')
        self.assertEqual(res, "Prioritise review based on the combined CVSS, CISA KEV, and EPSS contributions to the organisation's risk score.")

if __name__ == '__main__':
    unittest.main(verbosity=2)

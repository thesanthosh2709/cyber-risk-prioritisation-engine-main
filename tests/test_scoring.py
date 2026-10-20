import os
import sys
import unittest
import pandas as pd
import json
import math

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.data_loader import load_vulnerabilities, load_profiles
from src.scoring import score_vulnerabilities

class TestScoringEngine(unittest.TestCase):
    
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
        
    def test_01_bank_filtering(self):
        res = score_vulnerabilities(self.vuln_df, self.bank)
        products = set(p for lst in res['affected_critical_products'] for p in lst)
        self.assertTrue(products.issubset({'Core Banking Framework', 'Identity Provider SaaS'}))
        
    def test_02_startup_filtering(self):
        res = score_vulnerabilities(self.vuln_df, self.startup)
        products = set(p for lst in res['affected_critical_products'] for p in lst)
        self.assertTrue(products.issubset({'Cloud Database Engine', 'Web Application Firewall'}))
        
    def test_03_utility_filtering(self):
        res = score_vulnerabilities(self.vuln_df, self.utility)
        products = set(p for lst in res['affected_critical_products'] for p in lst)
        self.assertTrue(products.issubset({'Embedded IoT Gateway', 'Enterprise Router OS'}))
        
    def test_04_cvss_normalisation_and_contribution(self):
        # We test cvss norm and contri
        res = score_vulnerabilities(self.vuln_df, self.bank)
        row = res.iloc[0]
        expected_cvss_cont = 100 * 0.3 * (row['cvss_base_score'] / 10.0)
        self.assertAlmostEqual(row['cvss_contribution'], expected_cvss_cont, places=4)
        
    def test_05_epss_normalisation_and_contribution(self):
        res = score_vulnerabilities(self.vuln_df, self.bank)
        row = res.iloc[0]
        expected_epss_cont = 100 * 0.25 * row['first_epss']
        self.assertAlmostEqual(row['epss_contribution'], expected_epss_cont, places=4)
        
    def test_06_cisa_kev_true_contribution(self):
        res = score_vulnerabilities(self.vuln_df, self.bank)
        true_rows = res[res['cisa_kev'] == True]
        if not true_rows.empty:
            row = true_rows.iloc[0]
            expected_kev_cont = 100 * 0.45 * 1
            self.assertAlmostEqual(row['kev_contribution'], expected_kev_cont, places=4)
            
    def test_07_cisa_kev_false_contribution(self):
        res = score_vulnerabilities(self.vuln_df, self.bank)
        false_rows = res[res['cisa_kev'] == False]
        if not false_rows.empty:
            row = false_rows.iloc[0]
            self.assertEqual(row['kev_contribution'], 0.0)
            
    def test_08_org_specific_weights(self):
        res = score_vulnerabilities(self.vuln_df, self.startup)
        row = res.iloc[0]
        self.assertEqual(row['cvss_weight'], 0.2)
        self.assertEqual(row['cisa_kev_weight'], 0.2)
        self.assertEqual(row['first_epss_weight'], 0.6)
        
    def test_09_contributions_add_up(self):
        res = score_vulnerabilities(self.vuln_df, self.utility)
        for _, row in res.iterrows():
            total = row['cvss_contribution'] + row['kev_contribution'] + row['epss_contribution']
            self.assertAlmostEqual(total, row['risk_score'], places=4)
            
    def test_10_scores_in_range(self):
        res = score_vulnerabilities(self.vuln_df, self.startup)
        for _, row in res.iterrows():
            self.assertTrue(0 <= row['risk_score'] <= 100)
            
    def test_11_unique_cve_aggregation(self):
        res = score_vulnerabilities(self.vuln_df, self.bank)
        self.assertEqual(len(res), res['cve_id'].nunique())
        
    def test_12_representative_product_highest_score(self):
        # We find a CVE in the original df that has multiple matches for the bank
        bank_products = self.bank['critical_products']
        subset = self.vuln_df[self.vuln_df['product_name'].isin(bank_products)]
        dupes = subset[subset.duplicated(subset=['cve_id'], keep=False)]
        
        if not dupes.empty:
            sample_cve = dupes['cve_id'].iloc[0]
            cve_rows = dupes[dupes['cve_id'] == sample_cve].copy()
            
            cve_rows['cvss_norm'] = cve_rows['cvss_base_score'] / 10.0
            cve_rows['score'] = (
                100 * 0.3 * cve_rows['cvss_norm'] +
                100 * 0.45 * cve_rows['cisa_kev'].astype(int) +
                100 * 0.25 * cve_rows['first_epss']
            )
            max_score_row = cve_rows.loc[cve_rows['score'].idxmax()]
            
            res = score_vulnerabilities(self.vuln_df, self.bank)
            res_row = res[res['cve_id'] == sample_cve].iloc[0]
            
            self.assertEqual(res_row['representative_product'], max_score_row['product_name'])
            self.assertAlmostEqual(res_row['risk_score'], max_score_row['score'], places=4)
            
    def test_13_affected_critical_products_retains_all(self):
        res = score_vulnerabilities(self.vuln_df, self.bank)
        # Check an item that had multiple
        bank_products = self.bank['critical_products']
        subset = self.vuln_df[self.vuln_df['product_name'].isin(bank_products)]
        cve_counts = subset['cve_id'].value_counts()
        multi_cve = cve_counts[cve_counts > 1].index[0]
        
        expected_products = sorted(subset[subset['cve_id'] == multi_cve]['product_name'].unique().tolist())
        res_row = res[res['cve_id'] == multi_cve].iloc[0]
        
        self.assertEqual(res_row['affected_critical_products'], expected_products)
        
    def test_14_tie_breaking_is_deterministic(self):
        # To test determinism, we run it multiple times and ensure it's identical
        res1 = score_vulnerabilities(self.vuln_df, self.utility)
        res2 = score_vulnerabilities(self.vuln_df, self.utility)
        pd.testing.assert_frame_equal(res1, res2)
        
    def test_15_original_files_not_modified(self):
        for path, orig_mtime in self.orig_mtimes.items():
            self.assertEqual(os.path.getmtime(path), orig_mtime, f"{path} was modified!")

if __name__ == '__main__':
    unittest.main(verbosity=2)

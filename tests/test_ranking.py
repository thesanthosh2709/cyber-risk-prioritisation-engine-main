import os
import sys
import unittest
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.data_loader import load_vulnerabilities, load_profiles
from src.scoring import score_vulnerabilities
from src.ranking import rank_top_vulnerabilities

class TestRankingEngine(unittest.TestCase):
    
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
        
        cls.bank_scored = score_vulnerabilities(cls.vuln_df, cls.bank)
        cls.startup_scored = score_vulnerabilities(cls.vuln_df, cls.startup)
        cls.utility_scored = score_vulnerabilities(cls.vuln_df, cls.utility)
        
    def test_01_descending_risk_score_ordering(self):
        ranked = rank_top_vulnerabilities(self.bank_scored)
        scores = ranked['risk_score'].tolist()
        self.assertEqual(scores, sorted(scores, reverse=True))
        
    def test_02_exactly_5_results(self):
        ranked = rank_top_vulnerabilities(self.bank_scored)
        self.assertEqual(len(ranked), 5)
        
    def test_03_fewer_than_5_results_handled(self):
        # Create a small artificial scored df
        small_df = self.bank_scored.head(3).copy()
        ranked = rank_top_vulnerabilities(small_df)
        self.assertEqual(len(ranked), 3)
        self.assertEqual(ranked['rank'].tolist(), [1, 2, 3])
        
    def test_04_same_cve_never_twice(self):
        ranked = rank_top_vulnerabilities(self.utility_scored)
        self.assertEqual(len(ranked), ranked['cve_id'].nunique())
        
    def test_05_rank_numbers_exact(self):
        ranked = rank_top_vulnerabilities(self.startup_scored)
        self.assertEqual(ranked['rank'].tolist(), [1, 2, 3, 4, 5])
        
    def test_06_deterministic_tie_breaking(self):
        ranked1 = rank_top_vulnerabilities(self.bank_scored)
        ranked2 = rank_top_vulnerabilities(self.bank_scored)
        pd.testing.assert_frame_equal(ranked1, ranked2)
        
    def test_07_highest_risk_is_rank_1(self):
        ranked = rank_top_vulnerabilities(self.bank_scored)
        max_score = self.bank_scored['risk_score'].max()
        self.assertEqual(ranked.iloc[0]['rank'], 1)
        self.assertEqual(ranked.iloc[0]['risk_score'], max_score)
        
    def test_08_lowest_is_rank_5(self):
        ranked = rank_top_vulnerabilities(self.bank_scored)
        self.assertEqual(ranked.iloc[-1]['rank'], 5)
        # Should be less than or equal to rank 4
        self.assertLessEqual(ranked.iloc[-1]['risk_score'], ranked.iloc[3]['risk_score'])
        
    def test_09_representative_product_preserved(self):
        ranked = rank_top_vulnerabilities(self.startup_scored)
        self.assertIn('representative_product', ranked.columns)
        self.assertIsNotNone(ranked.iloc[0]['representative_product'])
        
    def test_10_affected_critical_products_preserved(self):
        ranked = rank_top_vulnerabilities(self.utility_scored)
        self.assertIn('affected_critical_products', ranked.columns)
        self.assertTrue(isinstance(ranked.iloc[0]['affected_critical_products'], list))
        
    def test_11_organization_info_preserved(self):
        ranked = rank_top_vulnerabilities(self.bank_scored)
        self.assertEqual(ranked.iloc[0]['organisation_id'], 'ORG-001')
        self.assertEqual(ranked.iloc[0]['organisation_name'], 'Global Retail Bank')
        
    def test_12_ranking_does_not_mutate_input(self):
        orig_len = len(self.bank_scored)
        orig_cols = list(self.bank_scored.columns)
        rank_top_vulnerabilities(self.bank_scored)
        self.assertEqual(len(self.bank_scored), orig_len)
        self.assertEqual(list(self.bank_scored.columns), orig_cols)
        
    def test_13_ranking_works_for_all_orgs(self):
        rb = rank_top_vulnerabilities(self.bank_scored)
        rs = rank_top_vulnerabilities(self.startup_scored)
        ru = rank_top_vulnerabilities(self.utility_scored)
        self.assertEqual(len(rb), 5)
        self.assertEqual(len(rs), 5)
        self.assertEqual(len(ru), 5)
        
    def test_14_ranking_receives_unique_cve_data(self):
        # bank_scored already asserted unique in test_scoring. We verify it here.
        self.assertEqual(len(self.bank_scored), self.bank_scored['cve_id'].nunique())
        ranked = rank_top_vulnerabilities(self.bank_scored)
        self.assertEqual(len(ranked), ranked['cve_id'].nunique())
        
    def test_15_original_files_not_modified(self):
        for path, orig_mtime in self.orig_mtimes.items():
            self.assertEqual(os.path.getmtime(path), orig_mtime, f"{path} was modified!")

if __name__ == '__main__':
    unittest.main(verbosity=2)

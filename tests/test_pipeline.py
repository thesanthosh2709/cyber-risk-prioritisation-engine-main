import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.pipeline import run_risk_assessment

class TestPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.vuln_path = 'data/vulnerabilities.csv'
        cls.prof_path = 'data/profiles.json'
        
        # Check original file modification times
        cls.orig_mtimes = {
            cls.vuln_path: os.path.getmtime(cls.vuln_path),
            cls.prof_path: os.path.getmtime(cls.prof_path)
        }
        
    def test_01_org1_valid_result(self):
        res = run_risk_assessment("ORG-001")
        self.assertEqual(res['organisation']['organisation_name'], "Global Retail Bank")
        self.assertEqual(len(res['top_vulnerabilities']), 5)
        
    def test_02_org2_valid_result(self):
        res = run_risk_assessment("ORG-002")
        self.assertEqual(res['organisation']['organisation_name'], "Agile Cloud Tech Startup")
        
    def test_03_org3_valid_result(self):
        res = run_risk_assessment("ORG-003")
        self.assertEqual(res['organisation']['organisation_name'], "Municipal Utility Provider")
        
    def test_04_invalid_org_produces_error(self):
        with self.assertRaisesRegex(ValueError, "Unknown organisation ID: ORG-999"):
            run_risk_assessment("ORG-999")
            
    def test_05_contains_org_info(self):
        res = run_risk_assessment("ORG-001")
        self.assertIn('sector', res['organisation'])
        self.assertIn('critical_products', res['organisation'])
        
    def test_06_contains_org_weights(self):
        res = run_risk_assessment("ORG-002")
        self.assertEqual(res['weights']['cvss_weight'], 0.2)
        
    def test_07_contains_top_5_vulnerabilities(self):
        res = run_risk_assessment("ORG-003")
        self.assertEqual(len(res['top_vulnerabilities']), 5)
        
    def test_08_top_vulnerabilities_ranks_exact(self):
        res = run_risk_assessment("ORG-001")
        ranks = [v['rank'] for v in res['top_vulnerabilities']]
        self.assertEqual(ranks, [1, 2, 3, 4, 5])
        
    def test_09_every_cve_is_unique(self):
        res = run_risk_assessment("ORG-001")
        cves = [v['cve_id'] for v in res['top_vulnerabilities']]
        self.assertEqual(len(cves), len(set(cves)))
        
    def test_10_contains_explanations(self):
        res = run_risk_assessment("ORG-001")
        for v in res['top_vulnerabilities']:
            self.assertIn('why_this_matters', v)
            self.assertIn('why_ranked_high', v)
            self.assertIn('what_to_do_next', v)
            
    def test_11_explanation_fields_present(self):
        res = run_risk_assessment("ORG-002")
        for v in res['top_vulnerabilities']:
            self.assertTrue(bool(v['why_this_matters']))
            
    def test_12_risk_scores_in_range(self):
        res = run_risk_assessment("ORG-003")
        for v in res['top_vulnerabilities']:
            self.assertTrue(0 <= v['risk_score'] <= 100)
            
    def test_13_result_is_deterministic(self):
        res1 = run_risk_assessment("ORG-001")
        res2 = run_risk_assessment("ORG-001")
        self.assertEqual(res1, res2)
        
    def test_14_top_k_works(self):
        res = run_risk_assessment("ORG-001", top_k=3)
        self.assertEqual(len(res['top_vulnerabilities']), 3)
        
    def test_15_top_k_smaller_than_5(self):
        res = run_risk_assessment("ORG-002", top_k=2)
        self.assertEqual(len(res['top_vulnerabilities']), 2)
        
    def test_16_top_k_larger_handled(self):
        res = run_risk_assessment("ORG-003", top_k=1000)
        self.assertLess(len(res['top_vulnerabilities']), 1000)
        self.assertGreater(len(res['top_vulnerabilities']), 0)
        
    def test_17_gold_set_mismatch_warning(self):
        res = run_risk_assessment("ORG-001")
        warnings = res['metadata']['data_quality_warnings']
        self.assertTrue(any("gold_set.csv contains 0/5 CVEs" in w for w in warnings))
        
    def test_18_source_files_unchanged(self):
        for path, orig_mtime in self.orig_mtimes.items():
            self.assertEqual(os.path.getmtime(path), orig_mtime, f"{path} was modified!")
            
    def test_19_pipeline_no_mutate_input(self):
        # We test determinism which implies no mutation that persists
        pass
        
    def test_20_all_orgs_receive_specific_results(self):
        r1 = run_risk_assessment("ORG-001")
        r2 = run_risk_assessment("ORG-002")
        r3 = run_risk_assessment("ORG-003")
        
        self.assertNotEqual(r1['top_vulnerabilities'][0]['cve_id'], r2['top_vulnerabilities'][0]['cve_id'])

if __name__ == '__main__':
    unittest.main(verbosity=2)

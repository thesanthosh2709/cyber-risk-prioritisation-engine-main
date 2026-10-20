import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Verify imports work
import app
from src.pipeline import run_risk_assessment

class TestStreamlitApp(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.vuln_path = 'data/vulnerabilities.csv'
        cls.prof_path = 'data/profiles.json'
        cls.orig_mtimes = {
            cls.vuln_path: os.path.getmtime(cls.vuln_path),
            cls.prof_path: os.path.getmtime(cls.prof_path)
        }

    def test_01_app_imports_successfully(self):
        # Already verified by the import above, but explicitly asserting
        self.assertTrue(hasattr(app, 'get_available_orgs'))
        
    def test_02_pipeline_imports_successfully(self):
        self.assertTrue(callable(run_risk_assessment))
        
    def test_03_org_options_derived(self):
        orgs = app.get_available_orgs()
        self.assertEqual(len(orgs), 3)
        self.assertEqual(orgs[0]['org_id'], 'ORG-001')
        
    def test_04_org1_analysis_triggers(self):
        res = run_risk_assessment('ORG-001')
        self.assertEqual(res['organisation']['organisation_name'], 'Global Retail Bank')
        
    def test_05_org2_analysis_triggers(self):
        res = run_risk_assessment('ORG-002')
        self.assertEqual(res['organisation']['organisation_name'], 'Agile Cloud Tech Startup')
        
    def test_06_org3_analysis_triggers(self):
        res = run_risk_assessment('ORG-003')
        self.assertEqual(res['organisation']['organisation_name'], 'Municipal Utility Provider')
        
    def test_07_top5_data_from_pipeline(self):
        res = run_risk_assessment('ORG-001')
        self.assertEqual(len(res['top_vulnerabilities']), 5)
        self.assertIn('rank', res['top_vulnerabilities'][0])
        
    def test_08_explanations_displayed_from_pipeline(self):
        res = run_risk_assessment('ORG-001')
        top1 = res['top_vulnerabilities'][0]
        self.assertIn('why_this_matters', top1)
        self.assertTrue(bool(top1['why_this_matters']))
        
    def test_09_score_contributions_from_pipeline(self):
        res = run_risk_assessment('ORG-001')
        top1 = res['top_vulnerabilities'][0]
        self.assertIn('cvss_contribution', top1)
        self.assertIn('kev_contribution', top1)
        self.assertIn('epss_contribution', top1)
        
    def test_10_source_datasets_unchanged(self):
        for path, orig_mtime in self.orig_mtimes.items():
            self.assertEqual(os.path.getmtime(path), orig_mtime, f"{path} was modified!")

if __name__ == '__main__':
    unittest.main(verbosity=2)

from src.pipeline import run_risk_assessment
import json

orgs = ['ORG-001', 'ORG-002', 'ORG-003']
for org in orgs:
    res = run_risk_assessment(org)
    print(f'\\nORG: {org}')
    for i, v in enumerate(res['top_vulnerabilities']):
        print(f"{i+1}. {v['cve_id']}")

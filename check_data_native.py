import csv
import json

def analyze_csv(filepath):
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    print(f"File: {filepath}")
    print(f"Total rows: {len(rows)}")
    if not rows: return
    print(f"Columns: {list(rows[0].keys())}")
    
    missing = {k: 0 for k in rows[0].keys()}
    cvss_scores = []
    epss_scores = []
    
    for row in rows:
        for k, v in row.items():
            if not v or v.strip() == '':
                missing[k] += 1
        try:
            cvss_scores.append(float(row.get('cvss_base_score', 0)))
        except ValueError:
            pass
            
        try:
            epss_scores.append(float(row.get('first_epss', 0)))
        except ValueError:
            pass
            
    print(f"Missing values: {missing}")
    if cvss_scores:
        print(f"CVSS Range: {min(cvss_scores)} - {max(cvss_scores)}")
    if epss_scores:
        print(f"EPSS Range: {min(epss_scores)} - {max(epss_scores)}")
    print()

analyze_csv('data/vulnerabilities.csv')
analyze_csv('data/gold_set.csv')

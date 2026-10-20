import os
import pandas as pd

from src.data_loader import load_vulnerabilities, load_profiles, load_gold_set, run_data_quality_report
from src.scoring import score_vulnerabilities
from src.ranking import rank_top_vulnerabilities
from src.explanations import add_explanations

def run_risk_assessment(organisation_id, top_k=5, 
                        vuln_path='data/vulnerabilities.csv', 
                        prof_path='data/profiles.json',
                        gold_path='data/gold_set.csv'):
    """
    End-to-end orchestration pipeline.
    """
    # 1. Load data
    vuln_df = load_vulnerabilities(vuln_path)
    profiles_data = load_profiles(prof_path)
    
    # 2. Validate organisation_id
    org_list = profiles_data.get('organizations', [])
    org_map = {org['org_id']: org for org in org_list}
    
    if organisation_id not in org_map:
        available = ", ".join(org_map.keys())
        raise ValueError(f"Unknown organisation ID: {organisation_id}. Available organisations: {available}.")
        
    org_profile = org_map[organisation_id]
    
    # Optional: check gold set for warning
    warnings = []
    try:
        gold_df = load_gold_set(gold_path)
        # Suppress prints from data loader or just calculate directly
        vuln_cves = set(vuln_df['cve_id'])
        gold_cves = set(gold_df['cve_id'])
        matching = gold_cves.intersection(vuln_cves)
        if len(matching) != len(gold_cves):
            warnings.append(f"gold_set.csv contains {len(matching)}/{len(gold_cves)} CVEs matching vulnerabilities.csv.")
    except Exception:
        pass
        
    # 3. Scoring
    scored = score_vulnerabilities(vuln_df, org_profile)
    if scored.empty:
        raise ValueError(f"No vulnerabilities found for organisation {organisation_id} critical products.")
        
    unique_cves_count = scored['cve_id'].nunique()
        
    # 4. Ranking
    ranked = rank_top_vulnerabilities(scored, top_k=top_k)
    
    # 5. Explanations
    explained = add_explanations(ranked)
    
    # 6. Structured Result
    # Prepare list of dictionaries for top vulnerabilities
    top_vulns = []
    for _, row in explained.iterrows():
        top_vulns.append({
            'rank': row['rank'],
            'cve_id': row['cve_id'],
            'representative_product': row['representative_product'],
            'affected_critical_products': row['affected_critical_products'],
            'cvss_base_score': row['cvss_base_score'],
            'cisa_kev': row['cisa_kev'],
            'first_epss': row['first_epss'],
            'cvss_contribution': row['cvss_contribution'],
            'kev_contribution': row['kev_contribution'],
            'epss_contribution': row['epss_contribution'],
            'risk_score': row['risk_score'],
            'dominant_factor': row['dominant_factor'],
            'why_this_matters': row['why_this_matters'],
            'why_ranked_high': row['why_ranked_high'],
            'what_to_do_next': row['what_to_do_next']
        })
        
    result = {
        'organisation': {
            'organisation_id': org_profile['org_id'],
            'organisation_name': org_profile['name'],
            'sector': org_profile.get('sector', ''),
            'risk_appetite': org_profile.get('risk_appetite', ''),
            'critical_products': org_profile.get('critical_products', [])
        },
        'weights': {
            'cvss_weight': org_profile['weight_modifiers']['cvss_weight'],
            'cisa_kev_weight': org_profile['weight_modifiers']['cisa_kev_weight'],
            'first_epss_weight': org_profile['weight_modifiers']['first_epss_weight']
        },
        'top_vulnerabilities': top_vulns,
        'metadata': {
            'total_source_records': len(vuln_df),
            'total_unique_cves_after_filtering': unique_cves_count,
            'top_k': top_k,
            'data_quality_warnings': warnings
        }
    }
    
    return result

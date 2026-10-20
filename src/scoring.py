import pandas as pd

def score_vulnerabilities(vuln_df, org_profile):
    """
    Filters and scores vulnerabilities for a specific organization profile.
    
    vuln_df: DataFrame loaded from vulnerabilities.csv (with safe types applied).
    org_profile: Dictionary representing the organization from profiles.json.
    """
    # Step 1: Filter by critical products
    critical_products = org_profile.get('critical_products', [])
    filtered_df = vuln_df[vuln_df['product_name'].isin(critical_products)].copy()
    
    if filtered_df.empty:
        return pd.DataFrame()
        
    # Get weights
    weights = org_profile.get('weight_modifiers', {})
    cvss_weight = weights.get('cvss_weight', 0.0)
    kev_weight = weights.get('cisa_kev_weight', 0.0)
    epss_weight = weights.get('first_epss_weight', 0.0)
    
    org_id = org_profile.get('org_id')
    org_name = org_profile.get('name')
    
    # Step 2: Normalise values
    filtered_df['cvss_norm'] = filtered_df['cvss_base_score'] / 10.0
    filtered_df['epss_norm'] = filtered_df['first_epss']
    filtered_df['kev_norm'] = filtered_df['cisa_kev'].astype(int)
    
    # Step 3 & 4: Score Contributions
    filtered_df['cvss_contribution'] = 100.0 * cvss_weight * filtered_df['cvss_norm']
    filtered_df['kev_contribution'] = 100.0 * kev_weight * filtered_df['kev_norm']
    filtered_df['epss_contribution'] = 100.0 * epss_weight * filtered_df['epss_norm']
    
    filtered_df['risk_score'] = (
        filtered_df['cvss_contribution'] +
        filtered_df['kev_contribution'] +
        filtered_df['epss_contribution']
    )
    
    # Pre-calculate affected products per CVE
    affected_products_map = (
        filtered_df.groupby('cve_id')['product_name']
        .apply(lambda x: sorted(list(set(x))))
        .to_dict()
    )
    
    # Step 5 & 7: Unique CVE Ranking & Determinism
    # Tie-breaker rule: risk_score DESC, cvss_base_score DESC, first_epss DESC, kev_norm DESC, product_name ASC
    # In pandas sort_values, we can set ascending=[False, False, False, False, True]
    
    filtered_df.sort_values(
        by=['risk_score', 'cvss_base_score', 'first_epss', 'kev_norm', 'product_name'],
        ascending=[False, False, False, False, True],
        inplace=True
    )
    
    # Drop duplicates keeps the first occurrence, which is the highest ranking according to our sort.
    dedup_df = filtered_df.drop_duplicates(subset=['cve_id'], keep='first').copy()
    
    # Step 6: Output
    dedup_df['representative_product'] = dedup_df['product_name']
    dedup_df['affected_critical_products'] = dedup_df['cve_id'].map(affected_products_map)
    dedup_df['organisation_id'] = org_id
    dedup_df['organisation_name'] = org_name
    dedup_df['cvss_weight'] = cvss_weight
    dedup_df['cisa_kev_weight'] = kev_weight
    dedup_df['first_epss_weight'] = epss_weight
    
    # Ensure correct columns
    out_cols = [
        'cve_id', 'product_name', 'representative_product', 'affected_critical_products',
        'cvss_base_score', 'cisa_kev', 'first_epss',
        'cvss_contribution', 'kev_contribution', 'epss_contribution', 'risk_score',
        'organisation_id', 'organisation_name',
        'cvss_weight', 'cisa_kev_weight', 'first_epss_weight'
    ]
    
    return dedup_df[out_cols].copy()

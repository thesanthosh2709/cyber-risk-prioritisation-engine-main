import pandas as pd

def get_dominant_factor(row):
    cvss_c = row['cvss_contribution']
    kev_c = row['kev_contribution']
    epss_c = row['epss_contribution']
    
    m = max(cvss_c, kev_c, epss_c)
    if cvss_c == kev_c == epss_c:
        return 'BALANCED'
        
    # If the max is close to another, could be balanced, but let's keep it simple: 
    # Just return the strictly largest, or balanced if there's a tie for max
    if sum(1 for x in [cvss_c, kev_c, epss_c] if x == m) > 1:
        return 'BALANCED'
        
    if m == cvss_c:
        return 'CVSS'
    elif m == kev_c:
        return 'CISA KEV'
    else:
        return 'EPSS'

def generate_why_this_matters(row):
    cve = row['cve_id']
    rep_prod = row['representative_product']
    org_name = row['organisation_name']
    affected = row['affected_critical_products']
    
    if len(affected) > 1:
        prods = ", ".join(affected)
        return f"This vulnerability ({cve}) affects {len(affected)} critical technologies for {org_name}: {prods}. The highest scoring instance was on {rep_prod}, making it directly relevant to the organisation's security priorities."
    else:
        return f"This vulnerability ({cve}) affects {rep_prod}, one of {org_name}'s critical technologies, so it is directly relevant to the organisation's security priorities."

def generate_why_ranked_high(row, dominant_factor):
    cvss = row['cvss_base_score']
    kev = row['cisa_kev']
    epss = row['first_epss']
    
    cvss_w = int(row['cvss_weight'] * 100)
    kev_w = int(row['cisa_kev_weight'] * 100)
    epss_w = int(row['first_epss_weight'] * 100)
    
    kev_text = "is listed in the CISA Known Exploited Vulnerabilities catalog" if kev else "is not marked as CISA KEV in the supplied dataset"
    
    text = (f"This vulnerability ranked highly because it has a CVSS base score of {cvss}, {kev_text}, "
            f"and has an EPSS estimate of {epss:.5f}. ")
            
    text += f"For this organisation, CVSS carries a {cvss_w}% weight, CISA KEV carries a {kev_w}% weight, and EPSS carries a {epss_w}% weight. "
    
    if dominant_factor != 'BALANCED':
        text += f"The {dominant_factor} metric was the dominant factor in this ranking."
    else:
        text += "The contributions were balanced across multiple metrics."
        
    return text

def generate_what_to_do_next(row, dominant_factor):
    kev = row['cisa_kev']
    
    if kev:
        if dominant_factor == 'EPSS':
            return "Prioritise investigation and remediation because this vulnerability is listed in CISA KEV. The EPSS contribution is also the largest contributor to this organisation's risk score."
        elif dominant_factor == 'CVSS':
            return "Prioritise investigation and remediation because this vulnerability is listed in CISA KEV. The CVSS contribution is the largest contributor to this organisation's risk score."
        elif dominant_factor == 'CISA KEV':
            return "Prioritise investigation and remediation because this vulnerability is listed in CISA KEV, which is also the largest contributor to this organisation's risk score."
        else:
            return "Prioritise investigation and remediation because this vulnerability is listed in CISA KEV."
    else:
        if dominant_factor == 'CVSS':
            return "Prioritise review and remediation because the CVSS contribution is the largest contributor to this organisation's risk score."
        elif dominant_factor == 'EPSS':
            return "Prioritise investigation because the EPSS contribution is the largest contributor to this organisation's risk score."
        else:
            return "Prioritise review based on the combined CVSS, CISA KEV, and EPSS contributions to the organisation's risk score."

def add_explanations(top_df):
    """
    Takes a Top 5 ranked DataFrame and appends explanation columns.
    Returns a new DataFrame.
    """
    if top_df is None or top_df.empty:
        return pd.DataFrame()
        
    df = top_df.copy()
    
    dominant_factors = []
    matters = []
    ranked_high = []
    next_steps = []
    
    for _, row in df.iterrows():
        dom = get_dominant_factor(row)
        dominant_factors.append(dom)
        
        matters.append(generate_why_this_matters(row))
        ranked_high.append(generate_why_ranked_high(row, dom))
        next_steps.append(generate_what_to_do_next(row, dom))
        
    df['dominant_factor'] = dominant_factors
    df['why_this_matters'] = matters
    df['why_ranked_high'] = ranked_high
    df['what_to_do_next'] = next_steps
    
    return df

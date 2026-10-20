import pandas as pd

def rank_top_vulnerabilities(scored_vulnerabilities, top_k=5):
    """
    Ranks the unique-CVE scored vulnerabilities and returns the top K.
    
    scored_vulnerabilities: DataFrame output from src/scoring.score_vulnerabilities
    top_k: Number of top vulnerabilities to return (default: 5)
    """
    if scored_vulnerabilities is None or scored_vulnerabilities.empty:
        return pd.DataFrame()
        
    df = scored_vulnerabilities.copy()
    
    # Ensure kev_norm logic exists for sorting purposes if not already present
    if 'kev_norm' not in df.columns:
        df['kev_norm'] = df['cisa_kev'].astype(int)
        
    # Sort deterministically
    df.sort_values(
        by=['risk_score', 'cvss_base_score', 'first_epss', 'kev_norm', 'cve_id'],
        ascending=[False, False, False, False, True],
        inplace=True
    )
    
    # Take top K
    top_df = df.head(top_k).copy()
    
    # Add rank column (1-indexed)
    top_df['rank'] = range(1, len(top_df) + 1)
    
    # Clean up temporary column if we added it just for ranking
    if 'kev_norm' in top_df.columns and 'kev_norm' not in scored_vulnerabilities.columns:
        top_df.drop(columns=['kev_norm'], inplace=True)
        
    # Reorder columns to put rank at the front if desired, but retaining all required cols is enough.
    # The requirement specifically mentions assigning rank.
    return top_df

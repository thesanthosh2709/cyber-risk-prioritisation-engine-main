import os
import json
import pandas as pd
import warnings

class DataValidationError(Exception):
    pass

class FileMissingError(Exception):
    pass

def _check_columns(df, required_columns, filename):
    missing_cols = [col for col in required_columns if col not in df.columns]
    if missing_cols:
        raise DataValidationError(f"Missing required columns in {filename}: {missing_cols}")

def load_vulnerabilities(filepath):
    if not os.path.exists(filepath):
        raise FileMissingError(f"Missing file: {filepath}")
    
    df = pd.read_csv(filepath)
    required = ['cve_id', 'product_name', 'cvss_base_score', 'cisa_kev', 'first_epss']
    _check_columns(df, required, filepath)
    
    # Safe convert
    try:
        df['cvss_base_score'] = pd.to_numeric(df['cvss_base_score'])
        df['first_epss'] = pd.to_numeric(df['first_epss'])
    except ValueError as e:
        raise DataValidationError(f"Numeric conversion failed in {filepath}: {e}")
        
    # Convert cisa_kev safely
    if df['cisa_kev'].dtype == object:
        df['cisa_kev'] = df['cisa_kev'].astype(str).str.lower().map({'true': True, 'false': False, '1': True, '0': False})
    else:
        df['cisa_kev'] = df['cisa_kev'].astype(bool)
        
    return df

def load_gold_set(filepath):
    if not os.path.exists(filepath):
        raise FileMissingError(f"Missing file: {filepath}")
    
    df = pd.read_csv(filepath)
    required = ['cve_id', 'product_name', 'cvss_base_score', 'cisa_kev', 'first_epss', 'practitioner_rank_bank', 'practitioner_rank_startup']
    _check_columns(df, required, filepath)
    
    try:
        df['cvss_base_score'] = pd.to_numeric(df['cvss_base_score'])
        df['first_epss'] = pd.to_numeric(df['first_epss'])
    except ValueError as e:
        raise DataValidationError(f"Numeric conversion failed in {filepath}: {e}")
        
    if df['cisa_kev'].dtype == object:
        df['cisa_kev'] = df['cisa_kev'].astype(str).str.lower().map({'true': True, 'false': False, '1': True, '0': False})
    else:
        df['cisa_kev'] = df['cisa_kev'].astype(bool)
        
    return df

def load_profiles(filepath):
    if not os.path.exists(filepath):
        raise FileMissingError(f"Missing file: {filepath}")
        
    with open(filepath, 'r') as f:
        data = json.load(f)
        
    if 'organizations' not in data:
        raise DataValidationError("Missing 'organizations' key in profiles.json")
        
    orgs = data['organizations']
    for org in orgs:
        required_keys = ['org_id', 'name', 'sector', 'risk_appetite', 'critical_products', 'weight_modifiers']
        missing = [k for k in required_keys if k not in org]
        if missing:
            raise DataValidationError(f"Profile missing required fields: {missing}")
            
        weights = org['weight_modifiers']
        required_weights = ['cvss_weight', 'cisa_kev_weight', 'first_epss_weight']
        missing_weights = [w for w in required_weights if w not in weights]
        if missing_weights:
            raise DataValidationError(f"Profile missing required weight modifiers: {missing_weights}")
            
    return data

def run_data_quality_report(vuln_df, gold_df, profiles):
    report = {}
    
    # Vulnerabilities
    report['vuln_row_count'] = len(vuln_df)
    report['vuln_missing_values'] = vuln_df.isnull().sum().to_dict()
    report['vuln_duplicate_cves'] = vuln_df['cve_id'].duplicated().sum()
    report['vuln_unique_products'] = vuln_df['product_name'].nunique()
    
    # Gold Set
    report['gold_row_count'] = len(gold_df)
    
    # Matching
    vuln_cves = set(vuln_df['cve_id'])
    gold_cves = set(gold_df['cve_id'])
    matching_cves = gold_cves.intersection(vuln_cves)
    report['gold_cves_in_vuln'] = len(matching_cves)
    
    print("=== DATA QUALITY REPORT ===")
    print(f"Vulnerabilities Row Count: {report['vuln_row_count']}")
    print(f"Vulnerabilities Missing Values: {sum(report['vuln_missing_values'].values())}")
    print(f"Vulnerabilities Duplicate CVEs: {report['vuln_duplicate_cves']}")
    print(f"Vulnerabilities Unique Products: {report['vuln_unique_products']}")
    print(f"Gold Set Row Count: {report['gold_row_count']}")
    print(f"Gold-set CVEs matching vulnerabilities.csv: {report['gold_cves_in_vuln']}/{report['gold_row_count']}")
    
    if report['gold_cves_in_vuln'] != report['gold_row_count']:
        msg = ("DATASET RELATIONSHIP WARNING: Gold-set CVEs are separate from the supplied "
               "vulnerability database and cannot be directly joined. Gold set will be treated "
               "as an independent benchmark/reference dataset.")
        print(f"\nWARNING: {msg}")
        warnings.warn(msg)
        
    return report

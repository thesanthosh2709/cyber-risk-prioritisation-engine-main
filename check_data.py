import pandas as pd
import json

df_vuln = pd.read_csv('data/vulnerabilities.csv')
print("Vulnerabilities Info:")
print(df_vuln.info())
print("\nMissing values:")
print(df_vuln.isnull().sum())
print("\ncvss_base_score range:", df_vuln['cvss_base_score'].min(), "-", df_vuln['cvss_base_score'].max())
print("cisa_kev unique:", df_vuln['cisa_kev'].unique())
print("first_epss range:", df_vuln['first_epss'].min(), "-", df_vuln['first_epss'].max())

df_gold = pd.read_csv('data/gold_set.csv')
print("\nGold Set Info:")
print(df_gold.info())
print("\nMissing values:")
print(df_gold.isnull().sum())

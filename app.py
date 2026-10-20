import streamlit as st
import pandas as pd
import altair as alt

from src.pipeline import run_risk_assessment
from src.data_loader import load_profiles

# --- Configuration ---
st.set_page_config(
    page_title="Cyber Risk Prioritisation Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Caching Data Loaders for UI Setup ---
@st.cache_data
def get_available_orgs():
    try:
        prof = load_profiles('data/profiles.json')
        return prof.get('organizations', [])
    except Exception as e:
        return []

# --- UI Setup ---
orgs = get_available_orgs()
if not orgs:
    st.error("Could not load organisation profiles. Please check data/profiles.json.")
    st.stop()

org_options = {f"{org['org_id']} — {org['name']}": org for org in orgs}

# --- Sidebar ---
st.sidebar.title("Organisation Configuration")
st.sidebar.markdown("Select an organisation profile to configure the risk engine.")

selected_org_label = st.sidebar.selectbox("Active Profile", list(org_options.keys()), label_visibility="collapsed")
selected_org = org_options[selected_org_label]

st.sidebar.markdown("### Profile Details")
st.sidebar.markdown(f"**Organisation:** {selected_org['name']}<br>**Sector:** {selected_org['sector']}<br>**Risk Appetite:** {selected_org['risk_appetite']}", unsafe_allow_html=True)

st.sidebar.markdown("**Critical Products:**")
for prod in selected_org.get('critical_products', []):
    st.sidebar.markdown(f"- {prod}")

st.sidebar.markdown("---")
analyze_clicked = st.sidebar.button("Analyse Vulnerability Risk", type="primary", use_container_width=True)

if analyze_clicked:
    with st.spinner("Executing deterministic risk assessment..."):
        try:
            result = run_risk_assessment(selected_org['org_id'])
            st.session_state['analysis_result'] = result
        except Exception as e:
            st.sidebar.error(f"Error during analysis: {str(e)}")

# --- Main Page Header ---
st.title("CYBER RISK PRIORITISATION ENGINE")
st.markdown("### Organisation-aware vulnerability prioritisation using: CVSS + CISA KEV + EPSS")
st.caption("Deterministic • Explainable • Local Dataset")
st.markdown("---")

if 'analysis_result' in st.session_state:
    res = st.session_state['analysis_result']
    org_info = res['organisation']
    meta = res['metadata']
    top_vulns = res['top_vulnerabilities']
    weights = res['weights']
    
    # --- Risk Overview ---
    highest_score = top_vulns[0]['risk_score'] if top_vulns else 0
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Overall Top Risk Score", f"{highest_score:.2f} / 100")
    with col2:
        st.metric("Unique CVEs Evaluated", meta['total_unique_cves_after_filtering'])
    with col3:
        st.metric("Critical Products", len(org_info['critical_products']))
    with col4:
        st.metric("Top Priorities", len(top_vulns))

    st.markdown("<br>", unsafe_allow_html=True)

    # --- Personalised Scoring Section ---
    st.markdown("#### Personalised Scoring Configuration")
    st.markdown("This ranking is organisation-specific. The selected organisation applies the following weights to calculate risk:")
    
    w_col1, w_col2, w_col3 = st.columns(3)
    w_col1.markdown(f"**CVSS:** {int(weights['cvss_weight'] * 100)}%")
    w_col2.markdown(f"**CISA KEV:** {int(weights['cisa_kev_weight'] * 100)}%")
    w_col3.markdown(f"**EPSS:** {int(weights['first_epss_weight'] * 100)}%")
    
    st.markdown("<br>", unsafe_allow_html=True)

    # --- Top 5 Section ---
    st.markdown("## Top 5 Vulnerabilities Requiring Attention")
    
    if not top_vulns:
        st.warning("No vulnerabilities found for the selected critical products.")
    
    for v in top_vulns:
        with st.container(border=True):
            # Headline
            st.markdown(f"### #{v['rank']} &nbsp; | &nbsp; {v['cve_id']} &nbsp; | &nbsp; Risk Score: {v['risk_score']:.2f} / 100")
            
            # Key Info
            info_col1, info_col2, info_col3, info_col4, info_col5 = st.columns(5)
            info_col1.markdown(f"**Representative Product:**<br>{v['representative_product']}", unsafe_allow_html=True)
            info_col2.markdown(f"**CVSS Base:**<br>{v['cvss_base_score']}", unsafe_allow_html=True)
            info_col3.markdown(f"**CISA KEV:**<br>{v['cisa_kev']}", unsafe_allow_html=True)
            info_col4.markdown(f"**EPSS:**<br>{v['first_epss']:.4f}", unsafe_allow_html=True)
            info_col5.markdown(f"**Dominant Factor:**<br>{v['dominant_factor']}", unsafe_allow_html=True)
            
            st.markdown(f"**Affected Critical Products:** {', '.join(v['affected_critical_products'])}")
            
            # Expandable Details
            with st.expander("View Vulnerability Details & Score Breakdown"):
                st.markdown("#### WHY THIS MATTERS")
                st.write(v['why_this_matters'])
                
                st.markdown("#### WHY IT RANKED HIGH")
                st.write(v['why_ranked_high'])
                
                st.markdown("#### WHAT TO DO NEXT")
                st.write(v['what_to_do_next'])
                
                st.markdown("#### SCORE BREAKDOWN")
                # Create a horizontal bar chart using Altair
                chart_data = pd.DataFrame({
                    "Metric": ["CVSS", "CISA KEV", "EPSS"],
                    "Contribution": [v['cvss_contribution'], v['kev_contribution'], v['epss_contribution']]
                })
                
                chart = alt.Chart(chart_data).mark_bar().encode(
                    x=alt.X('Contribution:Q', title='Score Contribution', scale=alt.Scale(domain=[0, 100])),
                    y=alt.Y('Metric:N', sort=None, title=''),
                    color=alt.Color('Metric:N', legend=None),
                    tooltip=['Metric', 'Contribution']
                ).properties(height=150)
                
                st.altair_chart(chart, use_container_width=True)

    # --- Data Quality Note ---
    if meta.get('data_quality_warnings'):
        st.markdown("<br>", unsafe_allow_html=True)
        st.info("Benchmark note: the supplied gold-set records are maintained separately and are not used in the live prioritisation pipeline.")

else:
    st.info("Select an organisation from the sidebar and click 'Analyse Vulnerability Risk' to begin the assessment.")

st.markdown("<br><br>", unsafe_allow_html=True)

# --- Methodology ---
with st.expander("METHODOLOGY"):
    st.markdown("""
    1. Vulnerabilities are filtered to the organisation's critical products.
    2. CVSS, CISA KEV and EPSS are combined using organisation-specific weights.
    3. Multiple product records for the same CVE are consolidated using the highest organisation-specific risk score.
    4. Top 5 unique CVEs are selected deterministically.
    5. Plain-English explanations are generated from the calculated evidence.
    """)

# --- Footer ---
st.markdown("---")
st.caption("Built for Hackathon Demonstration")
st.caption("Analysis is based on the supplied vulnerability and organisation datasets.")

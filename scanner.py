import pandas as pd

def export_report(results):
    df = pd.DataFrame(results)
    df.to_csv("scan_report.csv", index=False)
    st.success("📄 Report saved as scan_report.csv")

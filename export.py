from fpdf import FPDF
import pandas as pd

def export_to_pdf(content, filename="scan_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for line in content.split('\n'):
        pdf.multi_cell(0, 10, line)
    pdf.output(filename)

def export_to_csv(data_list, filename="scan_report.csv"):
    df = pd.DataFrame(data_list)
    df.to_csv(filename, index=False)

import hashlib
import pyshark
import pandas as pd
import datetime
import os
import sys
import matplotlib.pyplot as plt
import base64
import io
import socket
from fpdf import FPDF

# --- ASCII BANNER FUNCTION ---
def print_banner():
    print(r"""
  _   _      _  _______                    
 | \ | |    | ||__   __|                   
 |  \| | ___| |_  | |_ __ __ _  ___ ___    
 | . ` |/ _ \ __| | | '__/ _` |/ __/ _ \   
 | |\  |  __/ |_  | | | | (_| | (_|  __/   
 |_| \_|\___|\__| |_|_|  \__,_|\___\___|   
                                           
      [ AUTOMATED FORENSIC ANALYZER ]
    """)

class UniversalForensicTool:
    def __init__(self, pcap_path, investigator_name, case_number):
        self.pcap_path = pcap_path
        self.investigator_name = investigator_name
        self.case_number = case_number
        
        # Hashes
        self.ingress_sha256 = ""
        self.ingress_md5 = ""
        self.egress_sha256 = ""
        
        # Analysis Data
        self.packet_data = []
        self.audit_log = []
        self.suspicious_count = 0
        self.packet_number = 0
        self.start_time = datetime.datetime.now()
        
        # Dynamic Tracking
        self.source_counts = {}       
        self.destination_counts = {}  
        
        self.stats = {
            "DDoS": 0,
            "Suspicious IP": 0,
            "HTTP": 0
        }
        
        self.log_action("Tool initialized. Case ID: " + self.case_number)

    def log_action(self, message):
        """ Audit Trail Logger """
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        log_entry = f"[{timestamp}] {message}"
        self.audit_log.append(log_entry)
        print(log_entry)

    def calculate_hashes(self, stage="Ingress"):
        """ Calculates BOTH MD5 and SHA256 """
        self.log_action(f"Calculating {stage} Hashes for integrity verification...")
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        
        try:
            with open(self.pcap_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                    md5_hash.update(byte_block)
            
            sha256_result = sha256_hash.hexdigest()
            md5_result = md5_hash.hexdigest()
            
            if stage == "Ingress":
                self.ingress_sha256 = sha256_result
                self.ingress_md5 = md5_result
                self.log_action(f"Ingress SHA256: {sha256_result}")
            else:
                self.egress_sha256 = sha256_result
                if self.egress_sha256 == self.ingress_sha256:
                    self.log_action("Integrity Check: MATCH (Evidence not modified).")
                else:
                    self.log_action("Integrity Check: FAIL (Evidence modified!).")
            return True
            
        except FileNotFoundError:
            self.log_action(f"ERROR: File '{self.pcap_path}' not found.")
            return False

    def analyze_traffic(self):
        self.log_action(f"Starting analysis on {os.path.basename(self.pcap_path)}...")
        
        try:
            cap = pyshark.FileCapture(self.pcap_path, keep_packets=False)
        except Exception as e:
            self.log_action(f"PyShark Error: {e}")
            return

        try:
            for packet in cap:
                self.packet_number += 1
                try:
                    # Extraction
                    timestamp = packet.sniff_time.strftime('%H:%M:%S')
                    protocol = packet.highest_layer
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    length = int(packet.length)
                    
                    info_text = f"{protocol} Packet"
                    if 'TCP' in packet:
                        info_text = f"Src: {packet.tcp.srcport} -> Dst: {packet.tcp.dstport}"
                    elif 'UDP' in packet:
                        info_text = f"Src: {packet.udp.srcport} -> Dst: {packet.udp.dstport}"

                    # Tracking
                    self.source_counts[src_ip] = self.source_counts.get(src_ip, 0) + 1
                    self.destination_counts[dst_ip] = self.destination_counts.get(dst_ip, 0) + 1

                    # Detection Logic
                    alert = ""
                    row_classes = ["filter-all"] 
                    is_suspicious_behavior = False

                    # HTTP Check
                    if 'HTTP' in protocol:
                        row_classes.append("filter-http")
                        self.stats["HTTP"] += 1 

                    # Malware Check
                    if 'HTTP' in protocol and hasattr(packet.http, 'user_agent'):
                        ua = packet.http.user_agent.lower()
                        if "wget" in ua or "mirai" in ua or "curl" in ua or "python" in ua:
                            alert = "[CRITICAL: MALWARE TOOL DETECTED]"
                            row_classes.append("filter-malware")
                            row_classes.append("critical")
                            self.suspicious_count += 1
                            is_suspicious_behavior = True

                    # High Volume Source Check
                    if self.source_counts[src_ip] > 100:
                        if not is_suspicious_behavior: 
                            alert = "[WARNING: HIGH VOLUME SOURCE]"
                            row_classes.append("filter-malware")
                            row_classes.append("critical")
                            is_suspicious_behavior = True
                    
                    if is_suspicious_behavior:
                        self.stats["Suspicious IP"] += 1

                    # DDoS Victim Check
                    if self.destination_counts[dst_ip] > 500:
                        alert = "[CRITICAL: DDOS VICTIM]"
                        row_classes.append("filter-ddos")
                        row_classes.append("critical")
                        if self.destination_counts[dst_ip] % 100 == 0: 
                             self.suspicious_count += 1
                        self.stats["DDoS"] += 1

                    # Build Row
                    pdf_alert = alert if alert else ""
                    if alert:
                        final_info = f"<b>{alert}</b> {info_text}"
                    else:
                        final_info = info_text

                    final_class_string = " ".join(row_classes)

                    self.packet_data.append({
                        "No": self.packet_number,
                        "Time": timestamp,
                        "Source": src_ip,
                        "Destination": dst_ip,
                        "Protocol": protocol,
                        "Length": length,
                        "Info": final_info,      
                        "CleanInfo": pdf_alert + " " + info_text, 
                        "Class": final_class_string,
                        "IsAlert": bool(alert)
                    })

                except AttributeError:
                    continue 
            
            cap.close()
            self.log_action(f"Analysis complete. Found {self.suspicious_count} anomalies.")

        except Exception as e:
            self.log_action(f"Error: {e}")

    def generate_chart(self):
        """ Generates Pie Chart """
        self.log_action("Generating visualization charts...")
        labels = []
        sizes = []
        colors = []
        
        if self.stats["DDoS"] > 0:
            labels.append(f"DDoS ({self.stats['DDoS']})")
            sizes.append(self.stats["DDoS"])
            colors.append("#e67e22") 
        if self.stats["Suspicious IP"] > 0:
            labels.append(f"Suspicious ({self.stats['Suspicious IP']})")
            sizes.append(self.stats["Suspicious IP"])
            colors.append("#e74c3c") 
        if self.stats["HTTP"] > 0:
            labels.append(f"HTTP ({self.stats['HTTP']})")
            sizes.append(self.stats["HTTP"])
            colors.append("#3498db") 

        if not sizes: return None

        plt.figure(figsize=(6, 4))
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
        plt.title(f"Threat Distribution - Case {self.case_number}")
        plt.axis('equal') 
        plt.savefig("temp_chart.png")
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close()
        
        return image_base64

    def generate_pdf_report(self):
        """ Generates PDF matching your Template """
        self.log_action("Generating PDF Report...")
        
        pdf = FPDF()
        pdf.add_page()
        
        # 1. HEADER
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, "AUTOMATED FORENSIC ANALYSIS REPORT", ln=True, align='C')
        pdf.set_font("Arial", '', 10)
        pdf.cell(0, 6, f"Tool: NetForensics Analyzer v5.1 | Host: {socket.gethostname()}", ln=True, align='C')
        pdf.ln(10)
        
        # 2. CASE METADATA
        pdf.set_font("Arial", 'B', 10)
        pdf.set_fill_color(220, 220, 220)
        pdf.cell(0, 8, "1. HEADER & CASE METADATA", ln=True, fill=True)
        pdf.set_font("Arial", '', 9)
        pdf.cell(40, 6, "Case Ref ID:", 1); pdf.cell(0, 6, self.case_number, 1, ln=True)
        pdf.cell(40, 6, "Examiner:", 1); pdf.cell(0, 6, self.investigator_name, 1, ln=True)
        pdf.cell(40, 6, "Date (UTC):", 1); pdf.cell(0, 6, datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), 1, ln=True)
        pdf.ln(5)

        # 3. EVIDENCE ACQUISITION
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(0, 8, "2. EVIDENCE ACQUISITION & INTEGRITY", ln=True, fill=True)
        pdf.set_font("Arial", '', 9)
        pdf.cell(40, 6, "Target File:", 1); pdf.cell(0, 6, os.path.basename(self.pcap_path), 1, ln=True)
        pdf.cell(40, 6, "File Size:", 1); pdf.cell(0, 6, f"{os.path.getsize(self.pcap_path)} bytes", 1, ln=True)
        pdf.ln(2)
        pdf.set_font("Arial", 'B', 9); pdf.cell(0, 6, "Original Hash (Ingress):", ln=True)
        pdf.set_font("Courier", '', 8)
        pdf.cell(20, 6, "SHA256:", 0); pdf.cell(0, 6, self.ingress_sha256, ln=True)
        pdf.cell(20, 6, "MD5:", 0); pdf.cell(0, 6, self.ingress_md5, ln=True)
        pdf.ln(5)

        # 4. EXECUTIVE SUMMARY
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(0, 8, "3. EXECUTIVE SUMMARY", ln=True, fill=True)
        pdf.set_font("Arial", '', 9)
        pdf.cell(0, 6, f"Scan Duration: {datetime.datetime.now() - self.start_time}", ln=True)
        pdf.cell(0, 6, f"Total Packets Scanned: {self.packet_number}", ln=True)
        pdf.cell(0, 6, f"Total Threats Detected: {self.suspicious_count}", ln=True)
        pdf.ln(5)
        if os.path.exists("temp_chart.png"):
            pdf.image("temp_chart.png", x=60, w=90)
            pdf.ln(5)

        # 5. AUDIT TRAIL
        pdf.add_page()
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(0, 8, "5. AUDIT TRAIL / PROCESSING LOG", ln=True, fill=True)
        pdf.set_font("Courier", '', 8)
        for log in self.audit_log:
            pdf.multi_cell(0, 5, log)
        pdf.ln(5)

        # 6. CONCLUSION
        pdf.set_font("Arial", 'B', 10)
        pdf.set_fill_color(220, 220, 220)
        pdf.cell(0, 8, "6. CONCLUSION & INTEGRITY VERIFICATION", ln=True, fill=True)
        pdf.set_font("Arial", '', 9)
        pdf.cell(40, 6, "Final Hash (Egress):", 1); pdf.cell(0, 6, self.egress_sha256, 1, ln=True)
        match_status = "MATCH (Non-Destructive)" if self.ingress_sha256 == self.egress_sha256 else "FAIL (Tampered)"
        pdf.cell(40, 6, "Integrity Check:", 1); pdf.cell(0, 6, match_status, 1, ln=True)
        pdf.ln(5)
        pdf.set_font("Arial", 'I', 8)
        pdf.cell(0, 6, "Disclaimer: This report was generated automatically. No warranties implied.", align='C')

        report_name = f"Forensic_Report_{self.case_number}.pdf"
        pdf.output(report_name)
        print(f"[*] PDF REPORT GENERATED: {report_name}")
        
        if os.path.exists("temp_chart.png"):
            os.remove("temp_chart.png")

    def generate_html_report(self, chart_image_data=None):
        """ Generates HTML Report with Filters """
        if not self.packet_data: return
        
        chart_html = ""
        if chart_image_data:
            chart_html = f"""<div class="chart-container"><h3>Visual Threat Distribution</h3><img src="data:image/png;base64,{chart_image_data}"></div>"""

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Interactive Report - {self.case_number}</title>
            <style>
                body {{ font-family: sans-serif; margin: 20px; background: #f4f4f4; }}
                .metadata-box {{ background: #2c3e50; color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .controls {{ background: white; padding: 10px; margin-bottom: 20px; border-radius: 5px; }}
                .btn {{ padding: 10px; margin-right: 10px; cursor: pointer; font-weight: bold; border:none; border-radius:3px; }}
                .btn:hover {{ opacity: 0.8; }}
                .chart-container {{ text-align: center; background: white; padding: 10px; margin-bottom: 20px; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; background: white; }}
                th {{ background: #34495e; color: white; padding: 10px; text-align: left; }}
                td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
                tr.critical {{ background: #ffcccc; }}
                tr.filter-http {{ background: #e3f2fd; }}
            </style>
            <script>
                function filterTable(category) {{
                    var rows = document.querySelectorAll('tbody tr');
                    rows.forEach(row => {{
                        if (category === 'all') {{
                            row.style.display = '';
                        }} else {{
                            if (row.classList.contains(category)) {{
                                row.style.display = '';
                            }} else {{
                                row.style.display = 'none';
                            }}
                        }}
                    }});
                }}
            </script>
        </head>
        <body>
            <h1>DIGITAL FORENSIC DASHBOARD</h1>
            <div class="metadata-box">
                <p><strong>Case:</strong> {self.case_number} | <strong>Examiner:</strong> {self.investigator_name}</p>
                <p><strong>Hash (SHA256):</strong> {self.ingress_sha256}</p>
            </div>
            {chart_html}
            
            <div class="controls">
                <strong>FILTER DATA: </strong>
                <button class="btn" style="background:#34495e; color:white;" onclick="filterTable('filter-all')">SHOW ALL</button>
                <button class="btn" style="background:#e74c3c; color:white;" onclick="filterTable('filter-malware')">MALWARE / SUSPICIOUS IP</button>
                <button class="btn" style="background:#e67e22; color:white;" onclick="filterTable('filter-ddos')">DDOS TARGETS</button>
                <button class="btn" style="background:#3498db; color:white;" onclick="filterTable('filter-http')">HTTP TRAFFIC</button>
            </div>

            <table>
                <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Info</th></tr></thead>
                <tbody>
        """
        for row in self.packet_data:
            html_content += f"<tr class='{row['Class']}'><td>{row['Time']}</td><td>{row['Source']}</td><td>{row['Destination']}</td><td>{row['Info']}</td></tr>"
        
        html_content += "</tbody></table></body></html>"
        
        report_name = f"Report_Case_{self.case_number}.html"
        with open(report_name, "w") as f:
            f.write(html_content)
        print(f"[*] HTML REPORT GENERATED: {report_name}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    # --- PRINT BANNER HERE ---
    print_banner()
    
    inv_name = input("[?] Investigator Name: ").strip()
    case_num = input("[?] Case Number: ").strip()
    file_path = input("[?] Evidence File Path (.pcap): ").strip().replace('"', '')
    
    if os.path.exists(file_path):
        tool = UniversalForensicTool(file_path, inv_name, case_num)
        
        if tool.calculate_hashes(stage="Ingress"):
            tool.analyze_traffic()
            tool.calculate_hashes(stage="Egress")
            
            chart_base64 = tool.generate_chart() 
            tool.generate_html_report(chart_base64) 
            tool.generate_pdf_report()              
            
            print("\n[SUCCESS] Full Audit & Analysis Completed.")
            print("[INFO] You can now open the reports.")
    else:
        print(f"\n[!] ERROR: File not found.")
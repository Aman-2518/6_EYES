import os
from datetime import datetime


def generate_report_filename():
    folder_name = "Reports"

    # Create Reports folder if it doesn't exist
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    count = 1

    while True:
        filename = f"report{count:02}.txt"
        filepath = os.path.join(folder_name, filename)

        if not os.path.exists(filepath):
            return filepath

        count += 1


def generate_report(ip, version, scan_type, scan_results, security_score):

    filename = generate_report_filename()

    scan_names = {
        1: "Common Ports Scan",
        2: "Single Port Scan",
        3: "Custom Range Scan"
    }

    with open(filename, "w", encoding="utf-8") as file:

        # ===========================
        # HEADER
        # ===========================

        file.write("=" * 100 + "\n")
        file.write("NETWORK SECURITY SCANNER REPORT\n")
        file.write("=" * 100 + "\n\n")

        file.write(f"Target IP        : {ip}\n")
        file.write(f"IP Version       : IPv{version}\n")
        file.write(f"Scan Type        : {scan_names.get(scan_type, 'Unknown')}\n")
        file.write(f"Generated On     : {datetime.now().strftime('%d-%m-%Y')}\n")
        file.write(f"Generated Time   : {datetime.now().strftime('%H:%M:%S')}\n")

        file.write("\n")
        file.write("=" * 100 + "\n")
        file.write("SCAN RESULTS\n")
        file.write("=" * 100 + "\n\n")

        # ===========================
        # TABLE HEADER
        # ===========================

        file.write(
            f"{'STATE':<10}"
            f"{'PORT':<8}"
            f"{'DEFAULT':<18}"
            f"{'SERVICE':<18}"
            f"{'RISK':<10}"
            f"BANNER\n"
        )

        file.write("-" * 100 + "\n")

        # ===========================
        # SCAN RESULTS
        # ===========================

        for result in scan_results:

            risk = result.get("risk", {"risk": "-"})

            banner = result["banner"] if result["banner"] else "Not Available"

            file.write(
                f"{result['state']:<10}"
                f"{result['port']:<8}"
                f"{result['default_service']:<18}"
                f"{result['service'] if result['service'] else '-':<15}"
                f"{result['risk']['risk'] if result['risk'] else '-':<10}"
                f"{result['banner'] if result['banner'] else 'Not Available'}\n"
            )

        # ===========================
        # RISK SUMMARY
        # ===========================

        file.write("\n")
        file.write("=" * 100 + "\n")
        file.write("RISK ANALYSIS\n")
        file.write("=" * 100 + "\n\n")

        for result in scan_results:

            if result["state"] != "OPEN":
                continue

            risk = result["risk"]

            file.write(f"Port           : {result['port']}\n")
            file.write(f"Service        : {result['service']}\n")
            file.write(f"Risk           : {risk['risk']}\n")
            file.write(f"Reason         : {risk['reason']}\n")
            file.write(f"Recommendation : {risk['recommendation']}\n")
            file.write("-" * 100 + "\n")

        # ===========================
        # STATISTICS
        # ===========================

        total_ports = len(scan_results)
        open_ports = sum(1 for r in scan_results if r["state"] == "OPEN")
        closed_ports = total_ports - open_ports

        high = sum(
            1 for r in scan_results
            if r.get("risk", {}).get("risk") == "HIGH"
        )

        medium = sum(
            1 for r in scan_results
            if r.get("risk", {}).get("risk") == "MEDIUM"
        )

        low = sum(
            1 for r in scan_results
            if r.get("risk", {}).get("risk") == "LOW"
        )

        file.write("\n")
        file.write("=" * 100 + "\n")
        file.write("SCAN STATISTICS\n")
        file.write("=" * 100 + "\n\n")

        file.write(f"Total Ports Scanned : {total_ports}\n")
        file.write(f"Open Ports          : {open_ports}\n")
        file.write(f"Closed Ports        : {closed_ports}\n")
        file.write(f"High Risks          : {high}\n")
        file.write(f"Medium Risks        : {medium}\n")
        file.write(f"Low Risks           : {low}\n")

        # ===========================
        # SECURITY SCORE
        # ===========================

        file.write("\n")
        file.write("=" * 100 + "\n")
        file.write("OVERALL SECURITY SCORE\n")
        file.write("=" * 100 + "\n\n")

        file.write(f"Security Score : {security_score}/100\n")

    return filename
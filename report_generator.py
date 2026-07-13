import os
from datetime import datetime


def generate_report_filename():
    folder_name = "Reports"

    
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    count = 1

    while True:
        filename = f"report{count:02}.txt"
        filepath = os.path.join(folder_name, filename)

        if not os.path.exists(filepath):
            return filepath

        count += 1


def write_header(file):
    file.write("="*100 + "\n")
    file.write('6_EYES\n')
    file.write('NETWORK SECURITY SCANNER REPORT\n')
    file.write("="*100 + "\n")
    file.write(f"Generated On   : {datetime.now().strftime('%d-%m-%Y')}\n")
    file.write(f"Generated Time : {datetime.now().strftime('%H:%M:%S')}\n")
    file.write("\n")

def write_target_info(file, target_type, targets, scan_type):
    file.write("="*100 + "\n")
    file.write("TARGET INFORMATION\n")
    file.write("="*100 + "\n\n")
    if target_type == 1:
        file.write("Target Type : IP Address\n")
    else:
        file.write("Target Type : URL\n")
        
    for target in  targets :
        file.write(
            f"IP Address : {target['ip']}\n"
            f"IP Version : IPv{target['version']}\n"
            f"Hostname : {target['hostname']}\n\n"
        )
    
    scan_names = {
    1: "Common Ports Scan",
    2: "Single Port Scan",
    3: "Custom Range Scan"
    }
    file.write(f"Scan Type : {scan_names.get(scan_type, 'Unknown Scan')}\n")


def write_scan_results(file,scan_results):
    file.write('\n')
    file.write("="*100 + "\n")
    file.write("SCAN RESULT \n")
    file.write("="*100 + "\n\n")

    file.write(
    f"{'STATE':<10}"
    f"{'PORT':<8}"
    f"{'IP ADDRESS':<40}"
    f"{'SERVICE':<18}"
    f"{'RISK':<10}"
    f"BANNER\n"
    )

    file.write("-" * 100 + "\n")

    for result in scan_results:
        service = result["service"] if result["service"] else "-"
        risk = result["risk"]["risk"] if result["risk"] else "-"
        banner = result["banner"] if result["banner"] else "Not Available"

        file.write(
            f"{result['state']:<10}"
            f"{result['port']:<8}"
            f"{result['ip']:<40}"
            f"{service:<18}"
            f"{risk:<10}"
            f"{banner}\n"
        )


def write_risk_analysis(file, scan_results):
    file.write("\n")
    file.write("=" * 100 + "\n")
    file.write("RISK ANALYSIS\n")
    file.write("=" * 100 + "\n\n")

    for result in scan_results:

        if result["state"] != "OPEN":
            continue

        risk = result["risk"]
        file.write(f"IP Address     : {result['ip']}\n")
        file.write(f"Port           : {result['port']}\n")
        file.write(f"Service        : {result['service']}\n")
        file.write(f"Risk           : {risk['risk']}\n")
        file.write(f"Reason         : {risk['reason']}\n")
        file.write(f"Recommendation : {risk['recommendation']}\n")
        file.write("-" * 100 + "\n")



def write_statistics(file, scan_results, security_score):
    total_ports = len(scan_results)

    open_ports = sum(
        1 for r in scan_results
        if r["state"] == "OPEN"
        )

    closed_ports = total_ports - open_ports

    high = sum(
        1 for r in scan_results
        if r["risk"]["risk"] == "HIGH"
        )

    medium = sum(
        1 for r in scan_results
        if r["risk"]["risk"] == "MEDIUM"
        )

    low = sum(
        1 for r in scan_results
        if r["risk"]["risk"] == "LOW"
    )
    file.write("=" * 100 + "\n")
    file.write("SCAN STATISTICS\n")
    file.write("=" * 100 + "\n\n")

    file.write(f"Total Ports Scanned : {total_ports}\n")
    file.write(f"Open Ports          : {open_ports}\n")
    file.write(f"Closed Ports        : {closed_ports}\n")
    file.write(f"High Risks          : {high}\n")
    file.write(f"Medium Risks        : {medium}\n")
    file.write(f"Low Risks           : {low}\n\n")

    file.write("=" * 100 + "\n")
    file.write("OVERALL SECURITY SCORE\n")
    file.write("=" * 100 + "\n\n")

    file.write(f"Security Score : {security_score}/100\n")


def generate_report(target_type, targets, scan_type, scan_results, security_score):

    filename = generate_report_filename()

    with open(filename, "w", encoding="utf-8") as file:

        write_header(file)

        write_target_info(
            file,
            target_type,
            targets,
            scan_type
        )

        write_scan_results(
            file,
            scan_results
        )

        write_risk_analysis(
            file,
            scan_results
        )

        write_statistics(
            file,
            scan_results,
            security_score
        )

    return filename
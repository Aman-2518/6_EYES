import validator
import config
import port_scanner
import risk_analyzer
import report_generator

ip=input("Enter an IP address : ")

ip_version = validator.validate_ip(ip)
if ip_version:
    print(f"Valid IP address.\nVersion: IPv{ip_version}")
    scan_result = []
    try:
        scan_type = int(input("Choose Scan Type\n1. Common Ports\n2. Single Port\n3. Custom Range\n"))
        match scan_type:
            case 1:
                scan_result = port_scanner.common_port(ip, config.COMMON_PORTS,ip_version)
            case 2:
                port = int(input("Enter the port to scan: "))
                scan_result = port_scanner.single_port(ip, port,ip_version)
            case 3:
                start_port = int(input("Enter the starting port: "))
                end_port = int(input("Enter the ending port: "))
                scan_result = port_scanner.custom_range(ip, start_port, end_port,ip_version)
            case _:
                print("Invalid scan type.")
                exit()
    except ValueError:
        print("Invalid input. Please enter a number.")
        exit()
else :
    print("Invalid IP-address")
    exit()

risks = []

for result in scan_result:

    if result["state"] == "OPEN":
        risk = risk_analyzer.get_risk_info(result["service"])
    else:
        risk = {
            "risk": "-",
            "score_penalty": 0
        }

    result["risk"] = risk

    risks.append(risk)

security_score = risk_analyzer.calculate_security_score(risks)

'''
print("\n" + "=" * 140)

print(
    f"{'STATE':<8}"
    f"{'PORT':<8}"
    f"{'IP':<18}"
    f"{'DEFAULT':<15}"
    f"{'SERVICE':<15}"
    f"{'RISK':<10}"
    f"BANNER"
)

print("=" * 140)

for result in scan_result : 

    print(
        f"{result['state']:<8}"
        f"{result['port']:<8}"
        f"{ip:<18}"
        f"{result['default_service']:<20}"
        f"{result['service'] if result['service'] else '-':<15}"
        f"{result['risk']['risk'] if result['risk'] else '-':<10}"
        f"{result['banner'] if result['banner'] else 'Not Available'}"
    )
    
print(f"Security Score : {security_score}/100")'''


filename = report_generator.generate_report(
    ip,
    ip_version,
    scan_type,
    scan_result,
    security_score
)

print(f"\nReport saved successfully to: {filename}")
import os
import sys
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

# Add 6_eyes to Python path so we can import validator, port_scanner, etc.
sys.path.append(os.path.join(os.path.dirname(__file__), 'scanner'))


from scanner import validator
from scanner import config
from scanner import port_scanner
from scanner import risk_analyzer
from scanner import report_generator
from scanner import url_validator

class APIHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        # Enable CORS for development ease
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/reports":
            # List reports
            reports_dir = os.path.join(os.path.dirname(__file__), 'Reports')
            reports = []
            if os.path.exists(reports_dir):
                for f in os.listdir(reports_dir):
                    if f.endswith('.txt'):
                        filepath = os.path.join(reports_dir, f)
                        stat = os.stat(filepath)
                        reports.append({
                            "filename": f,
                            "size": stat.st_size,
                            "created": stat.st_mtime
                        })
            reports.sort(key=lambda x: x['created'], reverse=True)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(reports).encode('utf-8'))
            return

        elif path.startswith("/api/reports/"):
            filename = os.path.basename(path)
            reports_dir = os.path.join(os.path.dirname(__file__), 'Reports')
            filepath = os.path.join(reports_dir, filename)
            if os.path.exists(filepath) and os.path.isfile(filepath):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                with open(filepath, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Report not found")
            return

        # Serve static files
        if path == "/" or path == "":
            path = "/index.html"
        
        # Prevent directory traversal
        clean_path = path.lstrip('/')
        public_dir = os.path.join(os.path.dirname(__file__), 'public')
        filepath = os.path.join(public_dir, clean_path)

        if os.path.exists(filepath) and os.path.isfile(filepath):
            self.send_response(200)
            if filepath.endswith('.html'):
                self.send_header('Content-Type', 'text/html')
            elif filepath.endswith('.css'):
                self.send_header('Content-Type', 'text/css')
            elif filepath.endswith('.js'):
                self.send_header('Content-Type', 'application/javascript')
            elif filepath.endswith('.svg'):
                self.send_header('Content-Type', 'image/svg+xml')
            else:
                self.send_header('Content-Type', 'application/octet-stream')
            self.end_headers()
            with open(filepath, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "File not found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/scan":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode('utf-8'))
                return

            target_input = data.get('target', '').strip()
            scan_type = int(data.get('scan_type', 1))

            if not target_input:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Target is required"}).encode('utf-8'))
                return

            # Determine target type
            # 1 = IP Address, 2 = URL
            ip_version = validator.validate_ip(target_input)
            if ip_version:
                target_type = 1
                targets = [{
                    'ip': target_input,
                    'version': ip_version,
                    'hostname': None
                }]
            else:
                target_type = 2
                resolved = url_validator.resolve_domain(target_input)
                if not resolved['valid']:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": resolved['error']}).encode('utf-8'))
                    return
                targets = resolved['addresses']

            scan_result = []
            try:
                if scan_type == 1:
                    # Common Ports
                    for target in targets:
                        ip = target['ip']
                        version = target['version']
                        hostname = target.get('hostname')
                        result = port_scanner.common_port(ip, config.COMMON_PORTS, version, hostname)
                        for item in result:
                            item['ip'] = ip
                            item["version"] = version
                            item["hostname"] = hostname
                        scan_result.extend(result)
                elif scan_type == 2:
                    # Single Port
                    port = int(data.get('port', 80))
                    for target in targets:
                        ip = target['ip']
                        version = target['version']
                        hostname = target.get('hostname')
                        result = port_scanner.single_port(ip, port, version, hostname)
                        for item in result:
                            item['ip'] = ip
                            item["version"] = version
                            item["hostname"] = hostname
                        scan_result.extend(result)
                elif scan_type == 3:
                    # Custom Range
                    start_port = int(data.get('start_port', 1))
                    end_port = int(data.get('end_port', 1024))
                    for target in targets:
                        ip = target['ip']
                        version = target['version']
                        hostname = target.get('hostname')
                        result = port_scanner.custom_range(ip, start_port, end_port, version, hostname)
                        for item in result:
                            item['ip'] = ip
                            item["version"] = version
                            item["hostname"] = hostname
                        scan_result.extend(result)
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Invalid scan type"}).encode('utf-8'))
                    return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Scan failed: {str(e)}"}).encode('utf-8'))
                return

            # Risk analysis
            risks = []
            for result in scan_result:
                if result["state"] == "OPEN":
                    risk = risk_analyzer.get_risk_info(result["service"])
                else:
                    risk = {
                        "risk": "-",
                        "score_penalty": 0,
                        "reason": "Port is closed.",
                        "recommendation": "No action needed."
                    }
                result["risk"] = risk
                risks.append(risk)

            security_score = risk_analyzer.calculate_security_score(risks)
            
            # Generate file report
            filename = report_generator.generate_report(target_type, targets, scan_type, scan_result, security_score)
            
            response_data = {
                "targets": targets,
                "scan_type": scan_type,
                "scan_results": scan_result,
                "security_score": security_score,
                "report_file": os.path.basename(filename)
            }

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            return
        
        self.send_error(404, "Endpoint not found")

def run(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, APIHandler)
    print(f"Starting server on http://localhost:{port} ...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Stopping server.")

if __name__ == '__main__':
    run()

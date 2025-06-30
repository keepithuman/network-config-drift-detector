#!/usr/bin/env python3
"""
Network Configuration Drift Detector

Detects configuration drift in network devices by comparing current
configurations against established baselines.

Author: Network Automation Team
Version: 1.0.0
"""

import argparse
import difflib
import json
import logging
import re
import smtplib
import sys
import yaml
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib


class ConfigurationDriftDetector:
    """Main class for detecting network configuration drift."""
    
    def __init__(self, config_file: str):
        """Initialize drift detector with configuration."""
        self.config = self._load_config(config_file)
        self.setup_logging()
        self.results = []
        
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = self.config.get('logging', {}).get('level', 'INFO')
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        logging.basicConfig(
            level=getattr(logging, log_level),
            format=log_format,
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('drift_detector.log')
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _load_config(self, config_file: str) -> dict:
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Configuration file {config_file} not found")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"Error parsing configuration file: {e}")
            sys.exit(1)
    
    def connect_to_device(self, device_info: dict) -> Optional[str]:
        """Connect to device and retrieve configuration."""
        try:
            connection_params = {
                'device_type': device_info['device_type'],
                'host': device_info['ip'],
                'username': device_info.get('username', self.config['credentials']['username']),
                'password': device_info.get('password', self.config['credentials']['password']),
                'timeout': device_info.get('timeout', 30),
                'global_delay_factor': 2
            }
            
            # Add optional SSH key support
            if 'ssh_key' in device_info:
                connection_params['use_keys'] = True
                connection_params['key_file'] = device_info['ssh_key']
            
            self.logger.info(f"Connecting to {device_info['hostname']} ({device_info['ip']})")
            
            with ConnectHandler(**connection_params) as conn:
                # Get appropriate show command based on device type
                if 'cisco' in device_info['device_type']:
                    config_command = 'show running-config'
                elif 'juniper' in device_info['device_type']:
                    config_command = 'show configuration'
                elif 'arista' in device_info['device_type']:
                    config_command = 'show running-config'
                else:
                    config_command = device_info.get('config_command', 'show running-config')
                
                config = conn.send_command(config_command, delay_factor=2)
                self.logger.info(f"Successfully retrieved configuration from {device_info['hostname']}")
                return config
                
        except NetmikoTimeoutException:
            self.logger.error(f"Timeout connecting to {device_info['hostname']}")
            return None
        except NetmikoAuthenticationException:
            self.logger.error(f"Authentication failed for {device_info['hostname']}")
            return None
        except Exception as e:
            self.logger.error(f"Error connecting to {device_info['hostname']}: {str(e)}")
            return None
    
    def load_baseline_config(self, baseline_path: str) -> Optional[str]:
        """Load baseline configuration from file."""
        try:
            with open(baseline_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            self.logger.error(f"Baseline file not found: {baseline_path}")
            return None
        except Exception as e:
            self.logger.error(f"Error reading baseline file {baseline_path}: {str(e)}")
            return None
    
    def normalize_config(self, config: str, device_type: str) -> List[str]:
        """Normalize configuration by removing dynamic content and sorting."""
        lines = config.split('\n')
        normalized_lines = []
        
        # Get ignore patterns from config
        ignore_patterns = self.config.get('filtering', {}).get('ignore_patterns', [])
        
        # Default patterns to ignore for common dynamic content
        default_patterns = [
            r'^!.*Last configuration change.*',
            r'^!.*Time:.*',
            r'^!.*NVRAM config last updated.*',
            r'^.*uptime is.*',
            r'^.*System image file is.*',
            r'^.*bytes of.*memory.*',
            r'^.*line protocol is.*',
            r'^interface.*line protocol is up.*',
            r'^.*Current configuration.*bytes.*',
            r'^.*Last configuration change.*'
        ]
        
        all_patterns = ignore_patterns + default_patterns
        compiled_patterns = [re.compile(pattern) for pattern in all_patterns]
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Skip lines that match ignore patterns
            skip_line = False
            for pattern in compiled_patterns:
                if pattern.match(line):
                    skip_line = True
                    break
            
            if not skip_line:
                normalized_lines.append(line)
        
        return normalized_lines
    
    def detect_drift(self, current_config: str, baseline_config: str, device_info: dict) -> dict:
        """Detect configuration drift between current and baseline configs."""
        current_lines = self.normalize_config(current_config, device_info['device_type'])
        baseline_lines = self.normalize_config(baseline_config, device_info['device_type'])
        
        # Generate diff
        differ = difflib.unified_diff(
            baseline_lines,
            current_lines,
            fromfile='baseline',
            tofile='current',
            lineterm=''
        )
        
        diff_lines = list(differ)
        
        # Analyze changes
        changes = []
        
        for line in diff_lines:
            if line.startswith('+') and not line.startswith('+++'):
                changes.append({
                    'type': 'added',
                    'content': line[1:].strip(),
                    'severity': self._assess_change_severity(line[1:].strip())
                })
            elif line.startswith('-') and not line.startswith('---'):
                changes.append({
                    'type': 'removed',
                    'content': line[1:].strip(),
                    'severity': self._assess_change_severity(line[1:].strip())
                })
        
        # Calculate drift metrics
        total_baseline_lines = len(baseline_lines)
        changed_lines = len(changes)
        drift_percentage = (changed_lines / total_baseline_lines * 100) if total_baseline_lines > 0 else 0
        
        # Determine overall severity
        severities = [change['severity'] for change in changes]
        if 'critical' in severities:
            overall_severity = 'critical'
        elif 'high' in severities:
            overall_severity = 'high'
        elif 'medium' in severities:
            overall_severity = 'medium'
        else:
            overall_severity = 'low'
        
        drift_result = {
            'hostname': device_info['hostname'],
            'ip': device_info['ip'],
            'has_drift': len(changes) > 0,
            'drift_percentage': round(drift_percentage, 2),
            'changes_count': len(changes),
            'changes': changes,
            'severity': overall_severity,
            'timestamp': datetime.now().isoformat(),
            'baseline_hash': hashlib.md5(baseline_config.encode()).hexdigest()[:8],
            'current_hash': hashlib.md5(current_config.encode()).hexdigest()[:8]
        }
        
        # Add recommendations
        drift_result['recommendations'] = self._generate_recommendations(changes, device_info)
        
        return drift_result
    
    def _assess_change_severity(self, line: str) -> str:
        """Assess the severity of a configuration change."""
        line_lower = line.lower()
        
        # Critical security-related changes
        critical_keywords = [
            'no access-list', 'permit any any', 'no firewall',
            'no encryption', 'no authentication', 'enable password',
            'no aaa', 'no logging', 'no snmp-server community'
        ]
        
        # High impact changes
        high_keywords = [
            'access-list', 'route-map', 'ip route', 'vlan',
            'interface', 'no shutdown', 'shutdown', 'bgp',
            'ospf', 'eigrp', 'spanning-tree'
        ]
        
        # Medium impact changes
        medium_keywords = [
            'description', 'banner', 'hostname', 'domain-name',
            'ntp', 'logging', 'snmp-server'
        ]
        
        for keyword in critical_keywords:
            if keyword in line_lower:
                return 'critical'
        
        for keyword in high_keywords:
            if keyword in line_lower:
                return 'high'
        
        for keyword in medium_keywords:
            if keyword in line_lower:
                return 'medium'
        
        return 'low'
    
    def _generate_recommendations(self, changes: List[dict], device_info: dict) -> List[str]:
        """Generate recommendations based on detected changes."""
        recommendations = []
        
        critical_changes = [c for c in changes if c['severity'] == 'critical']
        high_changes = [c for c in changes if c['severity'] == 'high']
        
        if critical_changes:
            recommendations.append("CRITICAL: Security-related changes detected. Immediate review required.")
            recommendations.append("Verify changes are authorized and document in change management system.")
        
        if high_changes:
            recommendations.append("High-impact network changes detected. Validate network connectivity and performance.")
        
        if len(changes) > 10:
            recommendations.append("Large number of changes detected. Consider configuration management review.")
        
        # Device-specific recommendations
        if 'core' in device_info['hostname'].lower():
            recommendations.append("Core device changes detected. Monitor for network-wide impact.")
        
        return recommendations
    
    def process_single_device(self, device_info: dict) -> dict:
        """Process a single device for drift detection."""
        self.logger.info(f"Processing device: {device_info['hostname']}")
        
        # Get current configuration
        current_config = self.connect_to_device(device_info)
        if current_config is None:
            return {
                'hostname': device_info['hostname'],
                'ip': device_info['ip'],
                'status': 'connection_failed',
                'error': 'Failed to retrieve configuration',
                'timestamp': datetime.now().isoformat()
            }
        
        # Load baseline configuration
        baseline_config = self.load_baseline_config(device_info['baseline'])
        if baseline_config is None:
            return {
                'hostname': device_info['hostname'],
                'ip': device_info['ip'],
                'status': 'baseline_error',
                'error': 'Failed to load baseline configuration',
                'timestamp': datetime.now().isoformat()
            }
        
        # Detect drift
        drift_result = self.detect_drift(current_config, baseline_config, device_info)
        drift_result['status'] = 'success'
        
        return drift_result
    
    def run_drift_detection(self, max_workers: int = 5) -> List[dict]:
        """Run drift detection across all configured devices."""
        devices = self.config.get('devices', [])
        
        if not devices:
            self.logger.warning("No devices configured for drift detection")
            return []
        
        self.logger.info(f"Starting drift detection for {len(devices)} devices")
        
        results = []
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_device = {executor.submit(self.process_single_device, device): device 
                               for device in devices}
            
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.get('has_drift', False):
                        self.logger.warning(
                            f"Drift detected on {result['hostname']}: "
                            f"{result['changes_count']} changes, severity: {result['severity']}"
                        )
                    else:
                        self.logger.info(f"No drift detected on {result['hostname']}")
                        
                except Exception as e:
                    self.logger.error(f"Error processing device {device['hostname']}: {str(e)}")
                    results.append({
                        'hostname': device['hostname'],
                        'ip': device['ip'],
                        'status': 'processing_error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
        
        self.results = results
        return results
    
    def generate_summary_report(self, results: List[dict]) -> dict:
        """Generate summary report of drift detection results."""
        total_devices = len(results)
        successful_checks = len([r for r in results if r.get('status') == 'success'])
        devices_with_drift = len([r for r in results if r.get('has_drift', False)])
        failed_checks = total_devices - successful_checks
        
        compliance_rate = ((successful_checks - devices_with_drift) / successful_checks * 100) if successful_checks > 0 else 0
        
        # Severity breakdown
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for result in results:
            if result.get('has_drift') and 'severity' in result:
                severity_counts[result['severity']] += 1
        
        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_devices': total_devices,
                'successful_checks': successful_checks,
                'failed_checks': failed_checks,
                'devices_with_drift': devices_with_drift,
                'compliance_rate': f"{compliance_rate:.1f}%",
                'severity_breakdown': severity_counts
            },
            'devices': results
        }
    
    def send_notifications(self, report: dict):
        """Send notifications based on drift detection results."""
        notification_config = self.config.get('notifications', {})
        
        # Email notifications
        if notification_config.get('email', {}).get('enabled', False):
            self._send_email_notification(report, notification_config['email'])
        
        # Webhook notifications
        if notification_config.get('webhook', {}).get('enabled', False):
            self._send_webhook_notification(report, notification_config['webhook'])
    
    def _send_email_notification(self, report: dict, email_config: dict):
        """Send email notification of drift detection results."""
        try:
            devices_with_drift = [d for d in report['devices'] if d.get('has_drift', False)]
            
            if not devices_with_drift and not email_config.get('send_on_no_drift', False):
                return
            
            subject = f"Network Configuration Drift Report - {len(devices_with_drift)} devices affected"
            
            # Create email content
            msg = MIMEMultipart()
            msg['From'] = email_config.get('sender', 'drift-detector@company.com')
            msg['To'] = ', '.join(email_config['recipients'])
            msg['Subject'] = subject
            
            # HTML email body
            html_body = self._generate_html_email_body(report, devices_with_drift)
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            with smtplib.SMTP(email_config['smtp_server'], email_config.get('smtp_port', 587)) as server:
                if email_config.get('use_tls', True):
                    server.starttls()
                if 'username' in email_config:
                    server.login(email_config['username'], email_config['password'])
                
                server.send_message(msg)
            
            self.logger.info(f"Email notification sent to {len(email_config['recipients'])} recipients")
            
        except Exception as e:
            self.logger.error(f"Failed to send email notification: {str(e)}")
    
    def _generate_html_email_body(self, report: dict, devices_with_drift: List[dict]) -> str:
        """Generate HTML email body for drift report."""
        html = f"""
        <html>
        <body>
        <h2>Network Configuration Drift Report</h2>
        <p><strong>Generated:</strong> {report['timestamp']}</p>
        
        <h3>Summary</h3>
        <ul>
        <li>Total Devices Checked: {report['summary']['total_devices']}</li>
        <li>Devices with Drift: {report['summary']['devices_with_drift']}</li>
        <li>Compliance Rate: {report['summary']['compliance_rate']}</li>
        <li>Failed Checks: {report['summary']['failed_checks']}</li>
        </ul>
        """
        
        if devices_with_drift:
            html += "<h3>Devices with Configuration Drift</h3><table border='1' style='border-collapse: collapse;'>"
            html += "<tr><th>Hostname</th><th>IP Address</th><th>Changes</th><th>Severity</th><th>Recommendations</th></tr>"
            
            for device in devices_with_drift:
                recommendations = '<br>'.join(device.get('recommendations', []))
                html += f"""
                <tr>
                <td>{device['hostname']}</td>
                <td>{device['ip']}</td>
                <td>{device['changes_count']}</td>
                <td>{device['severity'].upper()}</td>
                <td>{recommendations}</td>
                </tr>
                """
            html += "</table>"
        
        html += "</body></html>"
        return html
    
    def _send_webhook_notification(self, report: dict, webhook_config: dict):
        """Send webhook notification of drift detection results."""
        try:
            devices_with_drift = [d for d in report['devices'] if d.get('has_drift', False)]
            
            payload = {
                'timestamp': report['timestamp'],
                'summary': report['summary'],
                'devices_with_drift': devices_with_drift,
                'alert_level': 'critical' if any(d.get('severity') == 'critical' for d in devices_with_drift) else 'warning'
            }
            
            response = requests.post(
                webhook_config['url'],
                json=payload,
                timeout=30,
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            
            self.logger.info("Webhook notification sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {str(e)}")
    
    def save_report(self, report: dict, output_file: str):
        """Save drift detection report to file."""
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self.logger.info(f"Report saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to save report: {str(e)}")


def main():
    """Main function to run drift detection."""
    parser = argparse.ArgumentParser(description='Network Configuration Drift Detector')
    parser.add_argument('--config', '-c', default='config.yaml', help='Configuration file path')
    parser.add_argument('--device', help='Check specific device IP')
    parser.add_argument('--baseline', help='Baseline configuration file for specific device')
    parser.add_argument('--output', '-o', default='drift-report.json', help='Output report file')
    parser.add_argument('--report-only', action='store_true', help='Generate report without notifications')
    parser.add_argument('--max-workers', type=int, default=5, help='Maximum number of worker threads')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Initialize drift detector
    try:
        detector = ConfigurationDriftDetector(args.config)
        
        if args.verbose:
            detector.logger.setLevel(logging.DEBUG)
        
        # Handle single device check
        if args.device and args.baseline:
            device_info = {
                'hostname': args.device,
                'ip': args.device,
                'device_type': 'cisco_ios',  # Default, should be configurable
                'baseline': args.baseline
            }
            
            result = detector.process_single_device(device_info)
            report = detector.generate_summary_report([result])
            
        else:
            # Run full drift detection
            results = detector.run_drift_detection(max_workers=args.max_workers)
            report = detector.generate_summary_report(results)
        
        # Save report
        detector.save_report(report, args.output)
        
        # Send notifications unless report-only mode
        if not args.report_only:
            detector.send_notifications(report)
        
        # Print summary to console
        print(f"\nDrift Detection Complete:")
        print(f"Total Devices: {report['summary']['total_devices']}")
        print(f"Devices with Drift: {report['summary']['devices_with_drift']}")
        print(f"Compliance Rate: {report['summary']['compliance_rate']}")
        print(f"Report saved to: {args.output}")
        
        # Exit with appropriate code
        if report['summary']['devices_with_drift'] > 0:
            sys.exit(1)  # Drift detected
        else:
            sys.exit(0)  # No drift
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()

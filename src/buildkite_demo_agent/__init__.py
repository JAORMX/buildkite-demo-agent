"""Buildkite Demo Agent - OSV Vulnerability Scanner."""

import asyncio
import json
import os
import sys
from typing import List, Optional
import argparse
from dotenv import load_dotenv

from .osv_agent import OSVAgent, OSVConfig


def parse_packages_from_file(file_path: str) -> List[dict]:
    """Parse packages from a JSON file.
    
    Expected format:
    [
        {"package_name": "requests", "ecosystem": "PyPI", "version": "2.25.0"},
        {"package_name": "lodash", "ecosystem": "npm", "version": "4.17.20"}
    ]
    """
    try:
        with open(file_path, 'r') as f:
            packages = json.load(f)
        
        # Validate package format
        for pkg in packages:
            required_keys = ['package_name', 'ecosystem', 'version']
            if not all(key in pkg for key in required_keys):
                raise ValueError(f"Package missing required keys: {required_keys}")
        
        return packages
    except Exception as e:
        print(f"Error parsing packages file: {e}", file=sys.stderr)
        sys.exit(1)


def parse_packages_from_args(packages_str: str) -> List[dict]:
    """Parse packages from command line argument.
    
    Format: "package1:ecosystem1:version1,package2:ecosystem2:version2"
    Example: "requests:PyPI:2.25.0,lodash:npm:4.17.20"
    """
    packages = []
    try:
        for pkg_str in packages_str.split(','):
            parts = pkg_str.strip().split(':')
            if len(parts) != 3:
                raise ValueError(f"Invalid package format: {pkg_str}. Expected format: package:ecosystem:version")
            
            packages.append({
                'package_name': parts[0],
                'ecosystem': parts[1],
                'version': parts[2]
            })
        return packages
    except Exception as e:
        print(f"Error parsing packages: {e}", file=sys.stderr)
        sys.exit(1)


async def main():
    """Main CLI entry point."""
    # Load environment variables
    load_dotenv()
    
    parser = argparse.ArgumentParser(
        description="OSV Vulnerability Scanner for Buildkite pipelines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single package
  buildkite-demo-agent --package requests --ecosystem PyPI --version 2.25.0
  
  # Scan multiple packages from command line
  buildkite-demo-agent --packages "requests:PyPI:2.25.0,lodash:npm:4.17.20"
  
  # Scan packages from file
  buildkite-demo-agent --packages-file packages.json
  
  # Get vulnerability details
  buildkite-demo-agent --vulnerability-id GHSA-9hjg-9r4m-mvj7
  
  # Use custom OSV server
  buildkite-demo-agent --osv-server http://localhost:3000 --package requests --ecosystem PyPI --version 2.25.0
        """
    )
    
    # Single package scanning
    parser.add_argument('--package', help='Package name to scan')
    parser.add_argument('--ecosystem', help='Package ecosystem (PyPI, npm, Go, etc.)')
    parser.add_argument('--version', help='Package version to scan')
    
    # Batch scanning
    parser.add_argument('--packages', help='Comma-separated packages in format: package:ecosystem:version')
    parser.add_argument('--packages-file', help='JSON file containing packages to scan')
    
    # Vulnerability details
    parser.add_argument('--vulnerability-id', help='Get details for specific vulnerability ID')
    
    # Configuration
    parser.add_argument('--osv-server', default='http://localhost:8080', 
                       help='OSV MCP server URL (default: http://localhost:8080)')
    parser.add_argument('--anthropic-api-key', help='Anthropic API key (can also use ANTHROPIC_API_KEY env var)')
    
    # Output options
    parser.add_argument('--output-format', choices=['json', 'text'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--output-file', help='Write output to file instead of stdout')
    
    # Buildkite specific
    parser.add_argument('--fail-on-vulnerabilities', action='store_true',
                       help='Exit with code 1 if vulnerabilities are found (useful for CI/CD)')
    parser.add_argument('--severity-threshold', choices=['low', 'medium', 'high', 'critical'], 
                       default='medium', help='Minimum severity to report (default: medium)')
    
    args = parser.parse_args()
    
    # Validate arguments
    scan_modes = [
        bool(args.package and args.ecosystem and args.version),
        bool(args.packages),
        bool(args.packages_file),
        bool(args.vulnerability_id)
    ]
    
    if sum(scan_modes) != 1:
        print("Error: Specify exactly one of: single package, packages list, packages file, or vulnerability ID", 
              file=sys.stderr)
        sys.exit(1)
    
    # Create configuration
    config = OSVConfig(
        osv_server_url=args.osv_server,
        anthropic_api_key=args.anthropic_api_key
    )
    
    try:
        # Initialize agent
        agent = OSVAgent(config)
        
        # Determine what to scan
        if args.vulnerability_id:
            # Get vulnerability details
            result = await agent.get_vulnerability_details(args.vulnerability_id)
            output = {"vulnerability_id": args.vulnerability_id, "details": result}
            
        elif args.package:
            # Single package scan
            result = await agent.scan_package(args.package, args.ecosystem, args.version)
            output = result.model_dump()
            
        elif args.packages:
            # Multiple packages from command line
            packages = parse_packages_from_args(args.packages)
            results = await agent.scan_packages_batch(packages)
            output = [result.model_dump() for result in results]
            
        elif args.packages_file:
            # Multiple packages from file
            packages = parse_packages_from_file(args.packages_file)
            results = await agent.scan_packages_batch(packages)
            output = [result.model_dump() for result in results]
        
        # Format output
        if args.output_format == 'json':
            output_str = json.dumps(output, indent=2)
        else:
            # Text format
            if isinstance(output, list):
                output_str = format_batch_results(output, args.severity_threshold)
            elif 'vulnerability_id' in output:
                output_str = f"Vulnerability {output['vulnerability_id']}:\n{output['details']}"
            else:
                output_str = format_single_result(output, args.severity_threshold)
        
        # Write output
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(output_str)
            print(f"Results written to {args.output_file}")
        else:
            print(output_str)
        
        # Check if we should fail on vulnerabilities
        if args.fail_on_vulnerabilities and has_vulnerabilities_above_threshold(output, args.severity_threshold):
            print(f"\n❌ Vulnerabilities found above {args.severity_threshold} severity threshold", file=sys.stderr)
            sys.exit(1)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def has_vulnerabilities_above_threshold(output, threshold: str) -> bool:
    """Check if vulnerabilities exist above the specified threshold."""
    severity_levels = ['low', 'medium', 'high', 'critical']
    threshold_index = severity_levels.index(threshold)
    
    if isinstance(output, list):
        for result in output:
            if check_single_result_threshold(result, threshold_index, severity_levels):
                return True
    else:
        return check_single_result_threshold(output, threshold_index, severity_levels)
    
    return False


def check_single_result_threshold(result: dict, threshold_index: int, severity_levels: List[str]) -> bool:
    """Check if a single result has vulnerabilities above threshold."""
    for i in range(threshold_index, len(severity_levels)):
        severity = severity_levels[i]
        key = f"{severity}_vulnerabilities"
        if key in result and result[key]:
            return True
    return False


def format_single_result(result: dict, threshold: str) -> str:
    """Format a single scan result for text output."""
    lines = []
    lines.append(f"📦 Package: {result['package_name']} ({result['ecosystem']}) v{result['version']}")
    lines.append(f"🔍 Vulnerabilities found: {result['vulnerabilities_found']}")
    
    if result['vulnerabilities_found'] > 0:
        if result['critical_vulnerabilities']:
            lines.append(f"🚨 Critical: {', '.join(result['critical_vulnerabilities'])}")
        if result['high_vulnerabilities']:
            lines.append(f"⚠️  High: {', '.join(result['high_vulnerabilities'])}")
        if result['medium_vulnerabilities']:
            lines.append(f"⚡ Medium: {', '.join(result['medium_vulnerabilities'])}")
        
        if result['recommendations']:
            lines.append("\n💡 Recommendations:")
            for rec in result['recommendations']:
                lines.append(f"  • {rec}")
    
    lines.append(f"\n📋 Summary: {result['summary']}")
    return '\n'.join(lines)


def format_batch_results(results: List[dict], threshold: str) -> str:
    """Format batch scan results for text output."""
    lines = []
    lines.append("🔍 Vulnerability Scan Results")
    lines.append("=" * 50)
    
    total_packages = len(results)
    vulnerable_packages = sum(1 for r in results if r['vulnerabilities_found'] > 0)
    
    lines.append(f"📊 Summary: {vulnerable_packages}/{total_packages} packages have vulnerabilities")
    lines.append("")
    
    for i, result in enumerate(results, 1):
        lines.append(f"{i}. {format_single_result(result, threshold)}")
        if i < len(results):
            lines.append("-" * 30)
    
    return '\n'.join(lines)


def cli():
    """CLI entry point for the buildkite-demo-agent command."""
    asyncio.run(main())


if __name__ == '__main__':
    cli()

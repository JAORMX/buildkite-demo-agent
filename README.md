# Buildkite Demo Agent - OSV Vulnerability Scanner

A simple agent that demonstrates using [pydantic.ai](https://ai.pydantic.dev/) with the [OSV (Open Source Vulnerabilities)](https://osv.dev/) MCP server in Buildkite pipelines via the [ToolHive Buildkite Plugin](https://github.com/StacklokLabs/toolhive-buildkite-plugin).

## Features

- 🔍 **Vulnerability Scanning**: Query OSV database for package vulnerabilities
- 🤖 **AI-Powered Analysis**: Uses Claude to analyze and categorize vulnerabilities
- 📊 **Multiple Output Formats**: JSON and human-readable text output
- 🚨 **CI/CD Integration**: Fail builds on critical vulnerabilities
- 📦 **Batch Processing**: Scan multiple packages at once
- 🔧 **Flexible Configuration**: Support for different ecosystems (PyPI, npm, Go, etc.)

## Quick Start

### Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) package manager
- Anthropic API key
- Access to OSV MCP server (via ToolHive)

### Installation

```bash
# Clone and setup
git clone <repository-url>
cd buildkite-demo-agent
uv sync

# Set up environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### Basic Usage

```bash
# Scan a single package
uv run buildkite-demo-agent \
  --package requests \
  --ecosystem PyPI \
  --version 2.25.0

# Scan multiple packages from file
uv run buildkite-demo-agent \
  --packages-file examples/packages.json \
  --output-format json

# Scan with command line packages
uv run buildkite-demo-agent \
  --packages "requests:PyPI:2.25.0,lodash:npm:4.17.20" \
  --severity-threshold high \
  --fail-on-vulnerabilities

# Get vulnerability details
uv run buildkite-demo-agent \
  --vulnerability-id GHSA-9hjg-9r4m-mvj7
```

## Command Line Options

### Scanning Modes

- `--package`, `--ecosystem`, `--version`: Scan a single package
- `--packages`: Comma-separated packages in format `package:ecosystem:version`
- `--packages-file`: JSON file containing packages to scan
- `--vulnerability-id`: Get details for specific vulnerability ID

### Configuration

- `--osv-server`: OSV MCP server URL (default: http://localhost:8080)
- `--anthropic-api-key`: Anthropic API key (or use ANTHROPIC_API_KEY env var)

### Output Options

- `--output-format`: Output format (`json` or `text`, default: `text`)
- `--output-file`: Write output to file instead of stdout

### CI/CD Options

- `--fail-on-vulnerabilities`: Exit with code 1 if vulnerabilities found
- `--severity-threshold`: Minimum severity to report (`low`, `medium`, `high`, `critical`)

## Package File Format

Create a JSON file with packages to scan:

```json
[
  {
    "package_name": "requests",
    "ecosystem": "PyPI",
    "version": "2.25.0"
  },
  {
    "package_name": "lodash",
    "ecosystem": "npm",
    "version": "4.17.20"
  },
  {
    "package_name": "github.com/gin-gonic/gin",
    "ecosystem": "Go",
    "version": "v1.7.0"
  }
]
```

## Buildkite Integration

The agent is designed to work with the [ToolHive Buildkite Plugin](https://github.com/StacklokLabs/toolhive-buildkite-plugin) to automatically provision OSV MCP servers.

### Example Pipeline

```yaml
steps:
  - label: "🔍 Vulnerability Scan"
    command: |
      uv sync
      uv run buildkite-demo-agent \
        --packages-file examples/packages.json \
        --fail-on-vulnerabilities \
        --severity-threshold high
    plugins:
      - StacklokLabs/toolhive#v0.0.1:
          server: "osv"
          transport: "streamable-http"
    env:
      ANTHROPIC_API_KEY: # Set in Buildkite environment
```

### Pipeline Features

- **Vulnerability Scanning**: Main scan with configurable severity thresholds
- **Security Reports**: Generate human-readable reports
- **Critical Checks**: Separate step for critical vulnerabilities only
- **Artifact Upload**: Save scan results as build artifacts
- **Flexible Execution**: Examples for single packages and batch scanning

## Architecture

### Components

1. **OSVAgent**: Main agent class using pydantic.ai
2. **VulnerabilityInfo**: Structured output model
3. **MCP Integration**: Connects to OSV server via Model Context Protocol
4. **CLI Interface**: Command-line interface for various use cases

### How It Works

1. **MCP Connection**: Agent connects to OSV MCP server via ToolHive
2. **AI Analysis**: Claude analyzes vulnerability data and categorizes by severity
3. **Structured Output**: Results formatted as structured data with recommendations
4. **CI/CD Integration**: Configurable failure conditions for pipeline integration

### Vulnerability Severity Classification

- **Critical**: Remote code execution, privilege escalation, data exfiltration
- **High**: Authentication bypass, significant data exposure, high-impact DoS
- **Medium**: Information disclosure, moderate DoS, input validation issues
- **Low**: Minor information leaks, low-impact issues

## Development

### Project Structure

```
├── src/buildkite_demo_agent/
│   ├── __init__.py          # CLI interface
│   └── osv_agent.py         # Main agent implementation
├── examples/
│   └── packages.json        # Example package list
├── .buildkite/
│   └── pipeline.yml         # Buildkite pipeline configuration
├── .env.example             # Environment variables template
└── pyproject.toml           # Project configuration
```

### Testing

```bash
# Install dependencies
uv sync

# Run linting
uv run ruff check src/

# Run type checking
uv run mypy src/

# Test with example data
uv run buildkite-demo-agent --packages-file examples/packages.json
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Environment Variables

- `ANTHROPIC_API_KEY`: Required for Claude API access
- `OSV_SERVER_URL`: OSV MCP server URL (optional, defaults to localhost:8080)

## Supported Ecosystems

The agent supports any ecosystem that OSV covers, including:

- **PyPI** (Python packages)
- **npm** (Node.js packages)
- **Go** (Go modules)
- **Maven** (Java packages)
- **NuGet** (.NET packages)
- **RubyGems** (Ruby packages)
- **Cargo** (Rust packages)
- And many more...

## Examples

### CI/CD Security Gate

```bash
# Fail build if any high or critical vulnerabilities found
uv run buildkite-demo-agent \
  --packages-file requirements.json \
  --severity-threshold high \
  --fail-on-vulnerabilities \
  --output-format json \
  --output-file security-report.json
```

### Security Audit Report

```bash
# Generate comprehensive security report
uv run buildkite-demo-agent \
  --packages-file all-dependencies.json \
  --output-format text \
  --output-file security-audit.txt \
  --severity-threshold low
```

### Specific Vulnerability Investigation

```bash
# Get detailed information about a specific vulnerability
uv run buildkite-demo-agent \
  --vulnerability-id CVE-2023-32681 \
  --output-format text
```

## License

This project is licensed under the Apache License 2.0.

## Links

- [pydantic.ai Documentation](https://ai.pydantic.dev/)
- [OSV Database](https://osv.dev/)
- [ToolHive Documentation](https://docs.stacklok.com/toolhive)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Buildkite Plugin](https://github.com/StacklokLabs/toolhive-buildkite-plugin)
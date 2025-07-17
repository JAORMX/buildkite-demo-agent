"""OSV Vulnerability Scanner Agent using pydantic.ai and MCP."""

import os
from dataclasses import dataclass
from typing import List, Optional
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.mcp import MCPServerSSE, MCPServerStreamableHTTP


class VulnerabilityInfo(BaseModel):
    """Structured output for vulnerability information."""
    package_name: str
    ecosystem: str
    version: str
    vulnerabilities_found: int
    critical_vulnerabilities: List[str]
    high_vulnerabilities: List[str]
    medium_vulnerabilities: List[str]
    recommendations: List[str]
    summary: str


@dataclass
class OSVConfig:
    """Configuration for OSV agent."""
    osv_server_url: str = "http://localhost:8080"
    anthropic_api_key: Optional[str] = None


class OSVAgent:
    """Agent for querying OSV vulnerability database via MCP."""

    def __init__(self, config: OSVConfig):
        """Initialize the OSV agent.

        Args:
            config: Configuration for the OSV agent
        """
        self.config = config
        
        # Set up Anthropic API key
        api_key = config.anthropic_api_key or os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY must be provided via config or environment variable")
        
        # Create MCP server connection for OSV - auto-detect transport from URL
        if config.osv_server_url.endswith('/sse'):
            self.osv_server = MCPServerSSE(config.osv_server_url)
        elif config.osv_server_url.endswith('/mcp') or config.osv_server_url.endswith('/mcp/'):
            # Remove trailing slash if present
            url = config.osv_server_url.rstrip('/')
            self.osv_server = MCPServerStreamableHTTP(f"{url}/")
        else:
            # Default to SSE transport with /sse path
            self.osv_server = MCPServerSSE(f"{config.osv_server_url}/sse")
        
        # Create the model
        model = AnthropicModel('claude-3-5-sonnet-20241022')
        
        # Create the agent with OSV MCP tools
        self.agent = Agent(
            model=model,
            mcp_servers=[self.osv_server],
            output_type=VulnerabilityInfo,
            system_prompt="""
You are a security vulnerability analyst assistant. You have access to OSV (Open Source Vulnerabilities) database tools:

1. query_vulnerability - Query for vulnerabilities affecting a specific package version
2. query_vulnerabilities_batch - Query for vulnerabilities affecting multiple packages at once  
3. get_vulnerability - Get details for a specific vulnerability by ID

When users ask about package vulnerabilities, you should:
1. Use the appropriate OSV tool to query for vulnerabilities
2. Analyze the severity and impact of found vulnerabilities
3. Categorize vulnerabilities by severity (critical, high, medium, low)
4. Provide actionable recommendations for remediation
5. Summarize the security posture of the package

For severity classification:
- Critical: Remote code execution, privilege escalation, data exfiltration
- High: Authentication bypass, significant data exposure, DoS with high impact
- Medium: Information disclosure, moderate DoS, input validation issues
- Low: Minor information leaks, low-impact issues

Always provide the package name, ecosystem, version, vulnerability count, categorized vulnerabilities, recommendations, and a clear summary.
""")

    async def scan_package(self, package_name: str, ecosystem: str, version: str) -> VulnerabilityInfo:
        """Scan a single package for vulnerabilities.
        
        Args:
            package_name: Name of the package to scan
            ecosystem: Package ecosystem (e.g., PyPI, npm, Go)
            version: Package version to scan
            
        Returns:
            VulnerabilityInfo with scan results
        """
        query = f"Scan {package_name} version {version} from {ecosystem} ecosystem for vulnerabilities"
        
        try:
            async with self.agent.run_mcp_servers():
                result = await self.agent.run(query)
                return result.output
        except Exception as e:
            # Return a basic error response if MCP fails
            return VulnerabilityInfo(
                package_name=package_name,
                ecosystem=ecosystem,
                version=version,
                vulnerabilities_found=0,
                critical_vulnerabilities=[],
                high_vulnerabilities=[],
                medium_vulnerabilities=[],
                recommendations=[f"Error scanning package: {str(e)}"],
                summary=f"Failed to scan {package_name}@{version}: {str(e)}"
            )

    async def scan_packages_batch(self, packages: List[dict]) -> List[VulnerabilityInfo]:
        """Scan multiple packages for vulnerabilities.
        
        Args:
            packages: List of package dictionaries with keys: package_name, ecosystem, version
            
        Returns:
            List of VulnerabilityInfo with scan results for each package
        """
        results = []
        for pkg in packages:
            result = await self.scan_package(
                pkg['package_name'], 
                pkg['ecosystem'], 
                pkg['version']
            )
            results.append(result)
        return results

    async def get_vulnerability_details(self, vulnerability_id: str) -> str:
        """Get detailed information about a specific vulnerability.
        
        Args:
            vulnerability_id: The OSV vulnerability ID
            
        Returns:
            Detailed vulnerability information as string
        """
        query = f"Get detailed information about vulnerability {vulnerability_id}"
        
        try:
            async with self.agent.run_mcp_servers():
                result = await self.agent.run(query)
                return result.output.summary
        except Exception as e:
            return f"Error retrieving vulnerability details: {str(e)}"
#!/usr/bin/env python3
"""
Clean Domain Deployment Script
Comprehensive domain cleanup and redeployment with port conflict prevention
"""

import requests
import json
import time
import sys
import os
import subprocess
import argparse
from typing import Dict, List, Tuple, Optional


class DomainDeployer:
    def __init__(self, server_host: str, api_port: int = 5000):
        self.base_url = f"http://{server_host}:{api_port}"
        self.server_host = server_host

    def cleanup_domain(self, domain_name: str) -> Tuple[bool, str]:
        """Completely clean up a domain including all components"""
        print(f"🧹 Cleaning up domain: {domain_name}")

        try:
            response = requests.post(
                f"{self.base_url}/api/domains/{domain_name}/cleanup",
                json={"components": ["processes", "nginx", "files", "database"]},
                headers={"Content-Type": "application/json"},
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    details = data.get("details", {})
                    print(
                        f"  ✅ Cleaned {len(details.get('components_cleaned', []))} components"
                    )
                    print(
                        f"  ✅ Stopped {len(details.get('stopped_processes', []))} processes"
                    )
                    print(f"  ✅ Removed {len(details.get('removed_files', []))} files")

                    if details.get("errors"):
                        # Check for nginx config test failure
                        nginx_config_error = False
                        for error in details["errors"]:
                            if (
                                "nginx config test failed" in str(error).lower()
                                and "no such file or directory" in str(error).lower()
                                and domain_name in str(error)
                            ):
                                nginx_config_error = True
                                break

                        if nginx_config_error:
                            print(f"  🔧 Detected nginx config issue, fixing...")
                            fix_success = self._fix_nginx_after_cleanup(domain_name)
                            if fix_success:
                                print(f"  ✅ Nginx configuration fixed")
                            else:
                                print(
                                    f"  ⚠️  Nginx fix attempt failed, but continuing deployment"
                                )
                        else:
                            print(f"  ⚠️  {len(details['errors'])} warnings/errors")
                            for error in details["errors"][:3]:  # Show first 3 errors
                                print(f"     - {error}")

                    return True, data.get("message", "Cleanup completed")
                else:
                    return False, data.get("error", "Cleanup failed")
            else:
                return False, f"HTTP {response.status_code}: {response.text}"

        except requests.RequestException as e:
            return False, f"Cleanup request failed: {str(e)}"

    def _fix_nginx_after_cleanup(self, domain_name: str) -> bool:
        """Fix nginx configuration after cleanup removes config files"""
        try:
            # Remove the broken symlink and reload nginx to clear the error
            ssh_commands = f"""
# Remove any broken symlinks for {domain_name}
rm -f /etc/nginx/sites-enabled/{domain_name}
rm -f /etc/nginx/sites-available/{domain_name}

# Reload nginx to clear the old config from memory
systemctl reload nginx

# Test nginx config (should now pass)
nginx -t
"""

            result = subprocess.run(
                ["ssh", f"root@{self.server_host}", ssh_commands],
                capture_output=True,
                text=True,
            )

            return result.returncode == 0

        except Exception as e:
            print(f"     ❌ Nginx fix failed: {e}")
            return False

    def check_available_ports(
        self, start_port: int = 3001, count: int = 20
    ) -> Tuple[bool, List[int]]:
        """Check for available ports starting from start_port"""
        print(f"🔍 Checking for {count} available ports starting from {start_port}")

        try:
            response = requests.post(
                f"{self.base_url}/api/check-ports",
                json={"startPort": start_port, "count": count},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    available_ports = data.get("availablePorts", [])
                    print(
                        f"  ✅ Found {len(available_ports)} available ports: {available_ports[:10]}"
                    )
                    return True, available_ports
                else:
                    print(f"  ❌ Port check failed: {data.get('error')}")
                    return False, []
            else:
                print(f"  ❌ HTTP {response.status_code}: {response.text}")
                return False, []

        except requests.RequestException as e:
            print(f"  ❌ Port check request failed: {str(e)}")
            return False, []

    def deploy_nextjs_app(
        self, domain_name: str, port: int, app_config: Dict
    ) -> Tuple[bool, Dict]:
        """Deploy Next.js application to specified port"""
        print(f"🚀 Deploying Next.js app for {domain_name} on port {port}")

        # Default minimal Next.js app
        # Default minimal Next.js app (App Router)
        default_files = {
            "package.json": json.dumps(
                {
                    "name": f"{domain_name.replace('.', '-')}-nextjs",
                    "version": "0.1.0",
                    "type": "module",
                    "scripts": {
                        "dev": "next dev",
                        "build": "next build",
                        "start": "next start -p $PORT",
                    },
                    "dependencies": {
                        "next": "14.0.3",
                        "react": "^18.2.0",
                        "react-dom": "^18.2.0",
                    },
                }
            ),
            # App Router layout & page
            "app/layout.js": """export const metadata={title:"App Ready",description:"Deployed with App Router"};
        import "./styles/globals.css";
        export default function RootLayout({children}){return(<html lang="en"><body>{children}</body></html>)}""",
            "app/page.js": f"""export default function Home() {{
        return (
            <main style={{{{
            padding:"2rem",fontFamily:"system-ui",maxWidth:"800px",margin:"0 auto",textAlign:"center"
            }}}}>
            <h1 style={{{{color:"#0070f3",fontSize:"3rem",margin:"0 0 1rem"}}}}>{domain_name}</h1>
            <p style={{{{fontSize:"1.1rem",color:"#666",marginBottom:"1.5rem"}}}}>
                Next.js (App Router) application successfully deployed!
            </p>
            <div style={{{{display:"flex",gap:"1rem",justifyContent:"center",flexWrap:"wrap"}}}}>
                <a href="/api/health" style={{{{padding:"0.75rem 1.25rem",background:"#0070f3",color:"#fff",
                textDecoration:"none",borderRadius:"8px"}}}}>Health Check</a>
                <a href="/api/info" style={{{{padding:"0.75rem 1.25rem",border:"2px solid #0070f3",color:"#0070f3",
                textDecoration:"none",borderRadius:"8px"}}}}>Server Info</a>
            </div>
            <footer style={{{{marginTop:"2rem",color:"#999",fontSize:"0.9rem"}}}}>
                <p>Deployed: {{new Date().toLocaleString()}}</p>
                <p>Port: {port} | Process Manager: PM2</p>
            </footer>
            </main>
        )
        }}""",
            # App Router API routes
            "app/api/health/route.js": """export async function GET(){return Response.json({
        status:"healthy",timestamp:new Date().toISOString(),uptime:process.uptime(),version:"1.0.0"
        })}""",
            "app/api/info/route.js": """export async function GET(){return Response.json({
        service:"Next.js Application",node_version:process.version,platform:process.platform,
        pid:process.pid,port:process.env.PORT||3000,environment:process.env.NODE_ENV||"development"
        })}""",
            # Minimal global CSS
            "app/styles/globals.css": """*{box-sizing:border-box}html,body{margin:0;padding:0;font-family:system-ui,-apple-system,Segoe UI,Roboto}
        a{color:inherit}""",
        }

        # Merge with custom files if provided
        files = {**default_files, **app_config.get("files", {})}

        # 🔧 Sanitize contents and enforce ESM app + CJS Next config
        files = self._sanitize_files(files)
        files = self._fix_server_event_handlers(files)  # <-- add this
        files = self._enforce_dual_module_mode(files)

        deploy_payload = {
            "name": domain_name.replace(".", "").replace("-", ""),
            "files": files,
            "deployConfig": {
                "port": port,
                "domain": domain_name,
                "environment": "production",
            },
        }

        try:
            response = requests.post(
                f"{self.base_url}/api/deploy/nodejs",
                json=deploy_payload,
                headers={"Content-Type": "application/json"},
                timeout=120,  # Longer timeout for deployment
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    print(f"  ✅ Deployment successful")
                    print(f"     - Port: {data.get('port')}")
                    print(f"     - Process Manager: {data.get('process_manager')}")
                    print(f"     - Files Path: {data.get('files_path')}")
                    return True, data
                else:
                    return False, {"error": data.get("error", "Deployment failed")}
            else:
                return False, {"error": f"HTTP {response.status_code}: {response.text}"}

        except requests.RequestException as e:
            return False, {"error": f"Deployment request failed: {str(e)}"}

    def configure_nginx_proxy(self, domain_name: str, port: int) -> Tuple[bool, str]:
        """Configure nginx reverse proxy for the domain via SSH"""
        print(f"🔧 Configuring nginx proxy for {domain_name} → port {port}")

        nginx_config = f"""server {{
    listen 80;
    server_name {domain_name};
    
    location / {{
        proxy_pass http://localhost:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}"""

        try:
            # Create the nginx config via SSH
            ssh_commands = f"""
# Create nginx config for {domain_name}
cat > /etc/nginx/sites-available/{domain_name} << 'EOF'
{nginx_config}
EOF

# Enable the site
ln -sf /etc/nginx/sites-available/{domain_name} /etc/nginx/sites-enabled/{domain_name}

# Test and reload nginx
nginx -t && systemctl reload nginx
"""

            result = subprocess.run(
                ["ssh", f"root@{self.server_host}", ssh_commands],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                print(f"  ✅ Nginx configured and reloaded via SSH")
                return True, "Nginx configuration successful"
            else:
                return False, f"SSH nginx config failed: {result.stderr}"

        except Exception as e:
            return False, f"Nginx configuration error: {str(e)}"

    def wait_for_app_startup(self, port: int, max_attempts: int = 10) -> bool:
        """Wait for the application to start up and respond"""
        print(f"⏳ Waiting for app startup on port {port}")

        for attempt in range(max_attempts):
            try:
                response = requests.get(
                    f"http://{self.server_host}:{port}/api/health", timeout=5
                )
                if response.status_code == 200:
                    print(f"  ✅ App is responding (attempt {attempt + 1})")
                    return True
            except requests.RequestException:
                pass

            if attempt < max_attempts - 1:
                print(f"  ⏳ Waiting... (attempt {attempt + 1}/{max_attempts})")
                time.sleep(3)

        print(f"  ⚠️  App may not be fully ready after {max_attempts} attempts")
        return False

    def verify_deployment(self, domain_name: str) -> Tuple[bool, str]:
        """Verify the deployment is working through the domain"""
        print(f"🔍 Verifying deployment for {domain_name}")

        try:
            # Test through domain
            response = requests.get(
                f"http://{self.server_host}/", headers={"Host": domain_name}, timeout=10
            )

            if response.status_code == 200:
                if domain_name in response.text:
                    print(f"  ✅ Domain {domain_name} is serving correctly")
                    return True, "Deployment verified successfully"
                else:
                    return False, "Domain serving content but may be wrong application"
            else:
                return False, f"Domain returned HTTP {response.status_code}"

        except requests.RequestException as e:
            return False, f"Verification failed: {str(e)}"

    def deploy_domain_complete(self, domain_name: str, app_config: Dict = None) -> bool:
        """Complete domain deployment workflow"""
        print(f"🎯 Starting complete deployment workflow for: {domain_name}")
        print("=" * 60)

        if app_config is None:
            app_config = {}

        # Step 1: Cleanup existing domain
        cleanup_success, cleanup_msg = self.cleanup_domain(domain_name)
        if not cleanup_success:
            print(f"❌ Cleanup failed: {cleanup_msg}")
            return False

        # Small delay to ensure cleanup is complete
        time.sleep(2)

        # Step 2: Check available ports
        port_check_success, available_ports = self.check_available_ports()
        if not port_check_success or not available_ports:
            print(f"❌ No available ports found")
            return False

        selected_port = available_ports[0]
        print(f"🎯 Selected port: {selected_port}")

        # Step 3: Deploy application
        deploy_success, deploy_data = self.deploy_nextjs_app(
            domain_name, selected_port, app_config
        )
        if not deploy_success:
            print(f"❌ Deployment failed: {deploy_data.get('error')}")
            return False

        # Step 4: Configure nginx reverse proxy
        nginx_success, nginx_msg = self.configure_nginx_proxy(
            domain_name, selected_port
        )
        if not nginx_success:
            print(f"⚠️  Nginx configuration failed: {nginx_msg}")

        # Step 5: Wait for startup
        self.wait_for_app_startup(selected_port)

        # Step 6: Verify deployment
        verify_success, verify_msg = self.verify_deployment(domain_name)
        if not verify_success:
            print(f"⚠️  Verification issue: {verify_msg}")

        print("\n" + "=" * 60)
        print(f"🎉 Deployment complete for {domain_name}")
        print(f"   🌐 URL: http://{domain_name}")
        print(f"   🔧 Direct: http://{self.server_host}:{selected_port}")
        print(f"   ❤️  Health: http://{domain_name}/api/health")
        print("=" * 60)

        return True

    def _sanitize_files(self, files: Dict[str, str]) -> Dict[str, str]:
        """
        - Remove next.config.js / next.config.mjs (we inject next.config.cjs elsewhere).
        - ALWAYS convert literal escapes (\\r\\n, \\n, \\r, \\t) to real characters.
        - Convert literal Unicode escapes like \\u00A9 to actual characters (e.g. ©).
        - Clean up any trailing literal \n sequences at EOF that some pipelines append.
        """
        import re

        def unescape_unicode_escapes(s: str) -> str:
            # Replace \uXXXX with the actual unicode character
            def repl(m):
                try:
                    return chr(int(m.group(1), 16))
                except ValueError:
                    return m.group(0)

            return re.sub(r"\\u([0-9a-fA-F]{4})", repl, s)

        out = {}
        for path, content in files.items():
            low = path.lower().strip()

            # Drop problematic Next config variants (we add next.config.cjs later)
            if low in ("next.config.js", "next.config.mjs"):
                print(
                    f"  🧽 Removing {path} from payload (will provide next.config.cjs)"
                )
                continue

            if isinstance(content, str):
                # 1) Unescape common literals globally (no heuristic)
                content = (
                    content.replace("\\r\\n", "\n")
                    .replace("\\n", "\n")
                    .replace("\\r", "\r")
                    .replace("\\t", "\t")
                )

                # 2) Convert \uXXXX anywhere (safe for JSX & strings)
                if "\\u" in content:
                    content = unescape_unicode_escapes(content)

                # 3) If the writer appended literal \n at EOF, normalize it
                content = re.sub(
                    r"(?:\\n)+\s*$", "\n", content
                )  # just in case any remain

            out[path] = content

        return out

    def _enforce_dual_module_mode(self, files: Dict[str, str]) -> Dict[str, str]:
        """
        Ensure package.json has "type":"module" and provide a single-line next.config.cjs (CommonJS).
        Works even if the deploy system writes files with literal \n.
        """
        files = dict(files)  # copy

        # Ensure package.json -> type: module and safe scripts
        pkg_raw = files.get("package.json")
        if isinstance(pkg_raw, str):
            try:
                pkg = json.loads(pkg_raw)
            except json.JSONDecodeError:
                # Try unescaping newlines if double-escaped
                pkg = json.loads(pkg_raw.replace("\\n", "\n"))
            pkg.setdefault("type", "module")
            pkg.setdefault("scripts", {})
            pkg["scripts"].setdefault("postinstall", "next telemetry disable")
            pkg["scripts"].setdefault("dev", "next dev")
            pkg["scripts"].setdefault(
                "build", 'NODE_OPTIONS="--max_old_space_size=1536" next build'
            )
            pkg["scripts"].setdefault("start", "next start -p ${PORT:-3000}")
            files["package.json"] = json.dumps(
                pkg, separators=(",", ":")
            )  # single-line JSON

        # Provide CommonJS Next config (no newlines to avoid literal \n issues)
        files["next.config.cjs"] = (
            "module.exports={output:'standalone',experimental:{esmExternals:'loose'},eslint:{ignoreDuringBuilds:true}};"
        )

        return files

    def _fix_server_event_handlers(self, files: Dict[str, str]) -> Dict[str, str]:
        """
        Remove server-side event handlers that break App Router builds.
        Currently strips onSubmit from app/contact/page.js.
        """
        import re

        path = "app/contact/page.js"
        if path in files and isinstance(files[path], str):
            before = files[path]
            # remove onSubmit={...} (simple, robust for our template)
            after = re.sub(r"\bonSubmit\s*=\s*{[^}]*}", "", before)
            if after != before:
                print("  🧽 Stripped onSubmit handler from app/contact/page.js")
            files[path] = after
        return files


def main():
    parser = argparse.ArgumentParser(description="Clean Domain Deployment")
    parser.add_argument("domain", help="Domain name to deploy")
    parser.add_argument("--server", default="75.119.141.162", help="Server IP address")
    parser.add_argument("--api-port", type=int, default=5000, help="API port")
    parser.add_argument("--config-file", help="JSON file with app configuration")

    args = parser.parse_args()

    # Load app configuration if provided
    app_config = {}
    if args.config_file:
        try:
            with open(args.config_file, "r") as f:
                app_config = json.load(f)
        except Exception as e:
            print(f"❌ Failed to load config file: {e}")
            sys.exit(1)

    # Initialize deployer
    deployer = DomainDeployer(args.server, args.api_port)

    # Run deployment
    success = deployer.deploy_domain_complete(args.domain, app_config)

    if success:
        print("🎉 All done!")
        sys.exit(0)
    else:
        print("❌ Deployment failed")
        sys.exit(1)


if __name__ == "__main__":
    main()

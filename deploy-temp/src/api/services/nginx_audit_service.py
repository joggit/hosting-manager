# src/api/services/nginx_audit_service.py - Nginx audit service
import subprocess
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple


class NginxAuditService:
    """Service for nginx/PM2 auditing functionality"""

    def __init__(self, deps):
        self.process_monitor = deps["process_monitor"]
        self.config = deps["config"]
        self.logger = deps["logger"]

        # Audit-related paths
        self.NGINX_SITES_AVAILABLE = Path("/etc/nginx/sites-available")
        self.NGINX_SITES_ENABLED = Path("/etc/nginx/sites-enabled")
        self.PM2_BIN = "pm2"
        self._port_regex = re.compile(r":(\d+)\b")

    def audit_nginx_pm2(self) -> Dict[str, Any]:
        """Full audit assembly"""
        try:
            # nginx -t
            try:
                out = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
                nginx_ok = out.returncode == 0
                nginx_test_output = ((out.stdout or "") + (out.stderr or "")).strip()
            except Exception as e:
                nginx_ok = False
                nginx_test_output = f"error: {e}"

            avail = self._list_dir(self.NGINX_SITES_AVAILABLE)
            enab = self._list_dir(self.NGINX_SITES_ENABLED)
            enabled_parsed = self._collect_enabled_confs()
            listeners = self._listening_ports()
            pm2 = self._pm2_table()
            port2app = self._map_ports_to_apps(pm2)
            cross = self._crosscheck(enabled_parsed, listeners, port2app)

            return {
                "nginx": {
                    "config_test": {"ok": nginx_ok, "output": nginx_test_output},
                    "available": avail,
                    "enabled": enab,
                    "enabled_parsed": enabled_parsed,
                },
                "listeners": sorted(list(listeners)),
                "pm2": pm2,
                "crosscheck": cross,
            }
        except Exception as e:
            self.logger.error(f"audit assembly failed: {e}")
            return {"error": str(e)}

    def _list_dir(self, p: Path) -> List[Dict[str, str]]:
        """List directory contents"""
        if not p.exists():
            return []
        items = []
        for entry in sorted(p.iterdir(), key=lambda x: x.name):
            try:
                items.append(
                    {
                        "name": entry.name,
                        "path": str(entry.resolve() if entry.exists() else entry),
                        "is_symlink": bool(entry.is_symlink()),
                        "target": str(entry.resolve()) if entry.is_symlink() else "",
                    }
                )
            except Exception:
                items.append(
                    {
                        "name": entry.name,
                        "path": str(entry),
                        "is_symlink": entry.is_symlink(),
                        "target": "",
                    }
                )
        return items

    def _parse_nginx_conf(self, conf_path: Path) -> Dict[str, Any]:
        """Parse nginx configuration file"""
        data: Dict[str, Any] = {
            "file": str(conf_path),
            "server_names": [],
            "roots": [],
            "proxy_pass_hosts": [],
            "upstreams": {},
            "port": None,
            "type": None,
            "listen_80": False,
            "listen_443": False,
        }

        try:
            text = conf_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return data

        # server_name
        for m in re.finditer(r"^\s*server_name\s+([^;]+);", text, flags=re.MULTILINE):
            names = m.group(1).strip()
            data["server_names"].extend([n.strip() for n in names.split() if n.strip()])

        # root
        for m in re.finditer(r"^\s*root\s+([^;]+);", text, flags=re.MULTILINE):
            data["roots"].append(m.group(1).strip())

        # listen flags
        if re.search(r"^\s*listen\s+80(\s|;)", text, flags=re.MULTILINE):
            data["listen_80"] = True
        if re.search(r"^\s*listen\s+443(\s|;)", text, flags=re.MULTILINE):
            data["listen_443"] = True

        # proxy_pass hosts
        for m in re.finditer(
            r"^\s*proxy_pass\s+https?://([^;\s]+);", text, flags=re.MULTILINE
        ):
            host = m.group(1).strip()
            data["proxy_pass_hosts"].append(host)

        # upstream blocks
        for up in re.finditer(
            r"upstream\s+([A-Za-z0-9_\.]+)\s*\{([^}]+)\}", text, flags=re.MULTILINE
        ):
            name, body = up.group(1), up.group(2)
            ports: List[str] = []
            for sm in re.finditer(r"server\s+127\.0\.0\.1:(\d+)", body):
                ports.append(sm.group(1))
            if ports:
                data["upstreams"][name] = ports

        # Decide type + primary port
        port: Optional[str] = None
        for host in data["proxy_pass_hosts"]:
            mm = self._port_regex.search(host)
            if mm:
                port = mm.group(1)
                break
        if not port:
            for ports in data["upstreams"].values():
                if ports:
                    port = ports[0]
                    break

        if port:
            data["port"] = int(port)
            data["type"] = "node"
        elif data["roots"]:
            data["type"] = "static"

        return data

    def _collect_enabled_confs(self) -> List[Dict[str, Any]]:
        """Collect enabled nginx configurations"""
        confs = []
        if not self.NGINX_SITES_ENABLED.exists():
            return confs
        for p in sorted(self.NGINX_SITES_ENABLED.iterdir(), key=lambda x: x.name):
            path = p.resolve() if p.is_symlink() else p
            if path.is_file():
                confs.append(self._parse_nginx_conf(path))
        return confs

    def _listening_ports(self) -> Set[int]:
        """Get listening ports"""
        ports: Set[int] = set()

        # Try 'ss -ltn' first
        try:
            result = subprocess.run(
                ["ss", "-ltn"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    m = self._port_regex.search(line)
                    if m:
                        try:
                            ports.add(int(m.group(1)))
                        except ValueError:
                            pass
                return ports
        except:
            pass

        # Fallback to netstat
        try:
            result = subprocess.run(
                ["netstat", "-lnt"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    m = self._port_regex.search(line)
                    if m:
                        try:
                            ports.add(int(m.group(1)))
                        except ValueError:
                            pass
        except:
            pass

        return ports

    def _pm2_table(self) -> Dict[str, Any]:
        """Get PM2 process table"""
        try:
            result = subprocess.run(
                [self.PM2_BIN, "jlist"], capture_output=True, text=True, timeout=10
            )
            pm2_result: Dict[str, Any] = {
                "ok": result.returncode == 0,
                "apps": [],
                "raw_error": None,
            }

            if result.returncode != 0:
                pm2_result["raw_error"] = result.stdout
                return pm2_result

            try:
                arr = json.loads(result.stdout)
            except Exception as e:
                pm2_result["raw_error"] = f"parse error: {e}"
                return pm2_result

            apps = []
            for a in arr:
                env = a.get("pm2_env", {}) or {}
                name = a.get("name")
                pm_id = a.get("pm_id")
                status = env.get("status")
                cwd = env.get("pm_cwd") or env.get("cwd") or ""
                port = (
                    (env.get("env") or {}).get("PORT")
                    or env.get("PORT")
                    or env.get("args_port")
                    or None
                )
                try:
                    port = int(port) if port else None
                except Exception:
                    port = None

                apps.append(
                    {
                        "name": name,
                        "pm_id": pm_id,
                        "status": status,
                        "cwd": cwd,
                        "port": port,
                    }
                )

            pm2_result["apps"] = apps
            return pm2_result

        except Exception as e:
            return {"ok": False, "apps": [], "raw_error": str(e)}

    def _map_ports_to_apps(self, pm2: Dict[str, Any]) -> Dict[int, str]:
        """Map ports to PM2 app names"""
        mapping: Dict[int, str] = {}
        for app in pm2.get("apps", []):
            p = app.get("port")
            if isinstance(p, int):
                mapping[p] = app.get("name") or ""
        return mapping

    def _crosscheck(
        self,
        enabled_confs: List[Dict[str, Any]],
        listeners: Set[int],
        port2app: Dict[int, str],
    ) -> List[Dict[str, Any]]:
        """Cross-check nginx configs with listening ports and PM2 apps"""
        out: List[Dict[str, Any]] = []
        for conf in enabled_confs:
            item: Dict[str, Any] = {
                "server_names": conf.get("server_names") or [],
                "file": conf.get("file"),
                "type": conf.get("type"),
                "root": (conf.get("roots") or [None])[0],
                "port": conf.get("port"),
                "listening": (
                    bool(conf.get("port") in listeners) if conf.get("port") else None
                ),
                "pm2_app": port2app.get(conf.get("port")) if conf.get("port") else None,
                "listen_80": conf.get("listen_80"),
                "listen_443": conf.get("listen_443"),
            }
            out.append(item)
        return out

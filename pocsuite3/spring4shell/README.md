# Spring4Shell PoC

Spring Framework (CVE-2022-22965) 远程代码执行验证/利用 PoC，pocsuite3 格式。

采用经 afrog 验证的 **GET 变异技术**（比 fscan 的 POST 方案更可靠）：通过
`class.module.classLoader.resources.context.parent.pipeline.first.*` 重配 Tomcat 的
AccessLogValve，向 `webapps/ROOT` 写入 JSP webshell，再经 webshell 执行命令。

## 文件清单

| 文件 | 漏洞编号 | 类型 | 说明 |
|------|---------|------|------|
| `cve_2022_22965_rce_poc.py` | CVE-2022-22965 | RCE | GET 变异写 webshell → 命令执行；verify/attack/shell 三模式结束前均自动删除 webshell（不留痕） |

## 影响范围

- Spring Framework <= 5.3.17 / 5.2.19
- JDK 9+，且以 WAR 部署在 Tomcat 上
- Spring Boot 可执行 JAR 默认部署**不受影响**

## 用法

```bash
# 验证模式（回显 /etc/passwd 即证明，匹配 root:.*?:[0-9]*:[0-9]*:）
pocsuite3 -r cve_2022_22965_rce_poc.py -u http://<target>

# 攻击模式（执行指定命令，默认 whoami）
pocsuite3 -r cve_2022_22965_rce_poc.py -u http://<target> --attack

# 自定义命令
pocsuite3 -r cve_2022_22965_rce_poc.py -u http://<target> --attack --command "id"
```

> 注：dropped webshell 调用 `Runtime.exec(cmd)`，命令按空格分词，**不支持** shell
> 管道 / 引号 / 重定向（如 `cat /etc/passwd`、`id`、`whoami` 等）。

## 参考

- https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- https://github.com/zan8in/afrog-pocs/blob/main/CVE/2022/CVE-2022-22965.yaml
- https://tanzu.vmware.com/security/cve-2022-22965

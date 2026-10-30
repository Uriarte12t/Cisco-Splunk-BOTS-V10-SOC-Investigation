# Cisco Splunk BOTS V10 | Blue Team SOC Investigation

**Cybersecurity Competition | Cal Poly Pomona | October 29, 2026**

**Focus:** Security Operations Center (SOC) Analysis • Threat Hunting • Incident Investigation • Splunk SPL

---

## 1. Project Overview

On October 29, 2026, I participated in **Cisco Splunk Boss of the SOC (BOTS) V10**, a timed, points-based cybersecurity competition at Cal Poly Pomona.

The competition challenged participants to investigate simulated cybersecurity incidents using Splunk, analyze security logs, identify suspicious activity, and answer investigative questions under time pressure.

As a Computer Information Systems student interested in networking, IT infrastructure, and cybersecurity, I participated to strengthen my hands-on security analysis skills and gain experience working with the types of logs and investigations encountered in a Security Operations Center.

This repository documents my work on **Scenario 1: Cats and Dawgs**, including my investigation methodology, SPL queries, findings, competition results, and lessons learned.

### Competition Highlights

| Metric | Result |
|---|---|
| Competition | Cisco Splunk Boss of the SOC (BOTS) V10 |
| Date | October 29, 2026 |
| Location | Cal Poly Pomona |
| Scenario | Scenario 1 — Cats and Dawgs |
| Correctly answered challenges | 6 |
| Points earned from those challenges | 2,113 |
| Primary tool | Splunk |
| Query language | Search Processing Language (SPL) |

*These results represent six successfully completed challenges, not completion of the entire competition.*

---

## 2. Scenario Background

The *Cats and Dawgs* scenario involved investigating suspicious activity affecting a fictional web application known as **Hotdog Hustlers**, associated with the Frothly environment.

The investigation required examining web traffic and server logs to understand normal application behavior, identify unusual requests, and distinguish legitimate users from potentially malicious activity.

I worked with several log sources, including:

- HTTP network traffic (`stream:http`)
- DNS events (`stream:dns`)
- Apache Tomcat access logs (`tomcat:access:log`)
- Apache Tomcat runtime logs (`tomcat:runtime:log`)
- Linux audit logs (`auditd:laurel`)
- Linux process execution logs (`auditd:laurel:syscall`)

These data sources provided different perspectives on the application, including incoming web requests, server behavior, authentication activity, and executed system commands.

---

## 3. Investigation Methodology

My general workflow followed five steps:

1. **Data discovery:** Identify available log sources and understand what information each contains.
2. **Baseline analysis:** Examine expected application requests and normal user behavior.
3. **Suspicious activity identification:** Look for unusual IP addresses, request patterns, URL paths, and HTTP responses.
4. **Log correlation:** Compare web traffic with Apache Tomcat and Linux audit logs.
5. **Evidence documentation:** Record relevant SPL queries, findings, and supporting screenshots.

I used Splunk's statistical and search commands to narrow down large volumes of security events and identify activity worth investigating.

---

## 4. Investigation 1 — Log Source Discovery

**Objective:** Identify available security data sources before beginning the investigation.

### SPL Query

```spl
| tstats count WHERE index=* BY index sourcetype
```

### What This Query Does

- `tstats` summarizes indexed data efficiently.
- `count` calculates the number of matching events.
- `BY index sourcetype` groups the results by their index and source type.

### Findings

The environment contained multiple data sources relevant to web application security, including HTTP traffic, DNS, Apache Tomcat logs, AWS events, and Linux audit records.

This helped me understand which logs could answer different investigation questions.

**Skill demonstrated:** SIEM data discovery and log source identification.

---

## 5. Investigation 2 — Web Server Identification

**Challenge #101: The Foray Begins**

**Objective:** Identify the software hosting the web application.

### SPL Query

```spl
index=main sourcetype="tomcat:access:log"
| head 20
```

### Findings

The access logs referenced Apache Tomcat log files and requests to the Hotdog Hustlers web application.

**Identified web server: Apache Tomcat**

### Why This Matters

Identifying the underlying web server helps security analysts understand the application's technology stack, relevant log formats, and potential attack surface.

**Skill demonstrated:** Web server identification and application log analysis.

---

## 6. Investigation 3 — Web Application Discovery

**Challenge #102: I've Got a Game Name, Yes I Do!**

**Objective:** Identify the application's domain and URL path.

### SPL Query

```spl
index=main sourcetype="stream:http" "hotdoghustlers"
| table _time src_ip dest_ip site url uri_path
```

### Findings

The HTTP logs revealed the application's domain and paths.

**Application:** `frothlydawgs.com/hotdoghustlers/`

### Why This Matters

Understanding a web application's domain and endpoints helps analysts establish normal activity and identify requests that do not match expected application behavior.

**Skill demonstrated:** HTTP traffic investigation and application endpoint discovery.

---

## 7. Investigation 4 — Player Activity and Geographic Analysis

**Challenge #103: We Are All Players**

**Objective:** Investigate the geographic distribution of users interacting with the application.

### SPL Query

```spl
index=main sourcetype="stream:http" uri_path="/hotdoghustlers*"
| iplocation src_ip
| stats dc(src_ip) AS unique_players BY Country
| sort -unique_players
```

### What This Query Does

- `iplocation` enriches public IP addresses with geographic information.
- `dc(src_ip)` counts distinct source IP addresses.
- `stats` groups results by country.

### Findings

The investigation compared activity associated with different countries and distinguished unique source IP addresses from total request volume.

One important consideration was that a large number of requests does not necessarily mean a large number of legitimate players. Automated activity can distort traffic-based measurements.

**Skill demonstrated:** IP geolocation, statistical analysis, and interpretation of network activity.

---

## 8. Investigation 5 — Suspicious IP Address Analysis

**Challenge #104: Some Are Bad Players**

**Objective:** Investigate an IP address exhibiting suspicious behavior.

### SPL Query

```spl
index=main sourcetype="stream:http" src_ip="185.211.32.18"
| sort 0 _time
| table _time src_ip http_method uri_path status
| head 40
```

### Findings

The source IP `185.211.32.18` generated numerous HTTP requests, including requests to multiple unrelated paths and application endpoints.

Examples included:

- `/robots.txt`
- `/clientaccesspolicy.xml`
- `/api/api-docs`
- `/trace.axd`
- `/crossdomain.xml`

The rapid sequence of requests suggested automated reconnaissance or vulnerability-probing activity.

### Security Significance

Unusual requests across many unrelated application paths can indicate an attempt to discover exposed files, vulnerable endpoints, or misconfigurations.

These patterns are useful indicators for further investigation, although they do not independently establish successful exploitation.

**Skill demonstrated:** Threat hunting, suspicious HTTP traffic analysis, and attacker infrastructure investigation.

---

## 9. Investigation 6 — Secondary Infrastructure Analysis

**Challenge #106: It's All About the Angle**

**Objective:** Investigate additional IP addresses involved in unusual web application activity.

### SPL Query

```spl
index=main sourcetype="stream:http"
| stats count AS requests dc(uri_path) AS unique_paths BY src_ip
| sort -requests
```

### Findings

The investigation identified another IP address of interest:

**`18.201.29.183`**

HTTP traffic from this address included requests to `/index.jsp` and attempts to create and retrieve `/check.txt`.

The observed sequence included:

```text
GET /index.jsp
PUT /check.txt
GET /check.txt
```

The `PUT` request returned an HTTP `201 Created` response, followed by a successful retrieval of the file.

### Security Significance

This behavior warranted further investigation because it demonstrated file-creation and retrieval activity on the web server.

**Skill demonstrated:** HTTP method analysis, IP investigation, and evidence correlation.

---

## 10. Investigation 7 — Session Cookie Analysis

**Challenge #107: The Files Are Inside the Computer**

**Objective:** Identify the session cookie referenced in suspicious web activity.

### SPL Query

```spl
index=main sourcetype="stream:http" "JSESSIONID"
| table _time src_ip http_method uri_path
| head 20
```

### Findings

The HTTP logs contained references to:

**`JSESSIONID`**

This is a session cookie commonly associated with Java web applications and Apache Tomcat.

### Security Significance

Session cookies help web applications associate requests with user sessions.

If attackers can steal, manipulate, or abuse session identifiers, they may attempt to interfere with authentication or session management.

The presence of a cookie in traffic does not, by itself, prove successful session hijacking.

**Skill demonstrated:** HTTP session analysis and web application security investigation.

---

## 11. Additional Investigation — Apache Tomcat and Linux Audit Logs

During the competition, I also investigated suspicious server-side behavior using Apache Tomcat runtime logs and Linux audit events.

The logs included Java session-handling exceptions and commands referencing files within the Tomcat web application directories.

For example:

```spl
index=main sourcetype="auditd:laurel:syscall" "EXECVE"
| spath path=EXECVE.ARGV{} output=args
| eval command=mvjoin(args," ")
| table _time command
```

This approach helped identify executed commands and examine the relationship between application behavior and host-level events.

Some of these investigations remained unresolved during the timed competition. I included them as learning experiences rather than claiming confirmed findings that the evidence did not establish.

**Skill demonstrated:** Linux process analysis, log correlation, and investigative troubleshooting.

---

## 12. Competition Results

I successfully answered six challenges during Scenario 1.

| Challenge | Title | Points |
|---|---|---:|
| #101 | The Foray Begins | 188 |
| #102 | I've Got a Game Name, Yes I Do! | 185 |
| #103 | We Are All Players | 440 |
| #104 | Some Are Bad Players | 445 |
| #106 | It's All About the Angle | 415 |
| #107 | The Files Are Inside the Computer | 440 |
| **Total** | **6 correctly answered challenges** | **2,113** |

My results reflect these completed challenges and do not represent an overall competition placement.

---

## 13. Technical Skills Demonstrated

| Skill | Application |
|---|---|
| SIEM Analysis | Navigating Splunk and querying security events |
| Search Processing Language | Using `stats`, `table`, `sort`, `tstats`, and `iplocation` |
| Threat Hunting | Investigating suspicious IPs and HTTP request patterns |
| Web Application Security | Understanding URLs, HTTP methods, cookies, and response codes |
| Log Correlation | Comparing HTTP, Tomcat, and Linux audit events |
| Incident Investigation | Building findings from timestamped security evidence |
| Documentation | Recording investigation steps and explaining technical observations |

---

## 14. Lessons Learned

Participating in this competition was a valuable opportunity to apply cybersecurity knowledge in a timed environment.

My biggest takeaways were:

- **Start with the data.** Understanding available log sources makes the investigation more efficient.
- **Develop a baseline.** Knowing what normal web application traffic looks like helps identify suspicious behavior.
- **Correlate evidence.** Web logs and host-level audit events provide different perspectives on the same incident.
- **Avoid unsupported conclusions.** Suspicious requests do not automatically mean an attack succeeded.
- **Manage time effectively.** In a cybersecurity competition, prioritizing achievable questions is important.
- **Document the process.** Clear evidence and explanations make technical work understandable to others.

This experience strengthened my interest in Security Operations Center investigations, network security, and hands-on infrastructure security.

---

## 15. Supporting Evidence

My supporting evidence includes screenshots of Splunk searches, investigation results, and the competition dashboard showing the six correctly completed challenges.

A redacted evidence document will be added here once reviewed for sensitive values and competition publication restrictions.

---

## Disclaimer

This repository documents my participation in an authorized cybersecurity competition using a simulated environment.

The findings reflect the evidence available during my investigation. They do not represent an independent production security assessment, a claim of successful exploitation, or completion of the entire competition.

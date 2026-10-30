# Cisco Splunk BOTS V10 | Blue Team SOC Investigation

**Cybersecurity Competition | Cal Poly Pomona | October 29, 2026**

**Focus Areas:** Security Operations Center (SOC) Operations • Threat Hunting • Incident Investigation • Network Security • Splunk SPL

---

## Project Overview

On October 29, 2026, I participated in **Cisco Splunk Boss of the SOC (BOTS) V10**, a timed, points-based cybersecurity competition at California State Polytechnic University, Pomona.

The competition challenged participants to investigate simulated cyberattacks, analyze large volumes of security logs, identify suspicious behavior, and answer investigative questions using Splunk.

As a Computer Information Systems student interested in networking, cloud infrastructure, and cybersecurity, I participated to strengthen my technical skills and gain practical experience with security investigations.

This project highlights my work on **Scenario 1: Cats and Dawgs**, where I investigated suspicious activity targeting a fictional web application.

Throughout the competition, I used **Splunk Search Processing Language (SPL)** to analyze network traffic, investigate IP addresses, examine web server activity, and correlate security events.

## Competition Highlights

| Category | Details |
|---|---|
| Competition | Cisco Splunk Boss of the SOC (BOTS) V10 |
| Event Date | October 29, 2026 |
| Location | Cal Poly Pomona |
| Competition Type | Timed Blue Team / SOC Cybersecurity Competition |
| Scenario | Cats and Dawgs |
| Successfully Completed Challenges | 6 |
| Points Earned | 2,113 |
| Primary Technology | Splunk |
| Query Language | Search Processing Language (SPL) |

**Note:** These results reflect six correctly answered challenges in Scenario 1, not completion of the entire competition.

---

## Scenario Background — Cats and Dawgs

The scenario involved a fictional organization called Frothly and its web-based game, *Hotdog Hustlers*.

The investigation focused on understanding legitimate application activity and identifying suspicious behavior that could indicate reconnaissance, vulnerability probing, or attempts to manipulate web application functionality.

The challenge required examining information from multiple sources, including:

- HTTP network traffic
- DNS events
- Apache Tomcat access logs
- Apache Tomcat runtime logs
- Linux audit logs
- Process execution activity

The primary goal was to reconstruct relevant activity and answer investigative questions using information available in the security logs.

---

## Tools and Technologies

| Technology | How I Used It |
|---|---|
| Splunk | Searched, filtered, and analyzed security events |
| Splunk SPL | Wrote queries to retrieve and correlate log data |
| HTTP Logs | Investigated web requests, HTTP methods, URLs, and response codes |
| Apache Tomcat | Examined web server and application activity |
| Linux Audit Logs | Investigated operating system events and process execution |
| IP Geolocation | Analyzed geographic information associated with source IP addresses |
| Network Traffic Analysis | Investigated communication patterns and suspicious requests |

---

## Investigation Methodology

My investigation followed a structured workflow commonly used in security analysis.

### 1. Discover Available Data Sources

I began by identifying the log sources available within the Splunk environment.

```spl
| tstats count WHERE index=* BY index sourcetype
```

This query helped identify the types of security data available for investigation.

The environment included HTTP traffic, Apache Tomcat logs, Linux audit events, and other sources relevant to understanding web application and host activity.

**What I learned:** Before investigating an incident, analysts need to understand what telemetry is available and what each log source can reveal.

### 2. Identify the Web Server

I examined Apache Tomcat access logs to understand the application's hosting environment.

```spl
index=main sourcetype="tomcat:access:log"
| head 20
```

The logs referenced Tomcat access log files and web application requests.

**Finding:** Apache Tomcat was identified as the web server.

**Security relevance:** Understanding the underlying server software helps analysts recognize normal log formats and identify technology-specific attack surfaces.

### 3. Discover the Web Application

Next, I investigated HTTP requests associated with the web application.

```spl
index=main sourcetype="stream:http" "hotdoghustlers"
| table _time src_ip dest_ip site url uri_path
```

The results revealed the application's domain and URL paths.

**Finding:** `frothlydawgs.com/hotdoghustlers/`

This established a baseline for understanding how users normally interacted with the application.

**What I learned:** Identifying legitimate application endpoints is useful when investigating requests that fall outside expected behavior.

### 4. Analyze Player Activity and IP Geolocation

I used Splunk's `iplocation` command to investigate the geographic distribution of source IP addresses.

```spl
index=main sourcetype="stream:http" uri_path="/hotdoghustlers*"
| iplocation src_ip
| stats dc(src_ip) AS unique_players BY Country
| sort -unique_players
```

This query enriched IP addresses with geographic information and counted distinct source IP addresses by country.

An important lesson was distinguishing **unique source IP addresses from total request volume**, since automated traffic can distort activity counts.

**Skills practiced:** IP enrichment, statistical analysis, and interpreting security telemetry.

### 5. Investigate Suspicious IP Activity

I analyzed HTTP activity associated with a suspicious source IP.

```spl
index=main sourcetype="stream:http" src_ip="185.211.32.18"
| sort 0 _time
| table _time src_ip http_method uri_path status
| head 40
```

The logs showed requests to multiple unrelated web application paths, including:

- `/robots.txt`
- `/clientaccesspolicy.xml`
- `/api/api-docs`
- `/trace.axd`
- `/crossdomain.xml`

Several requests occurred within a very short period.

**Finding:** The request pattern was consistent with automated reconnaissance or vulnerability probing.

**Security relevance:** Security analysts investigate unusual request frequency, unexpected paths, and HTTP response codes to identify potentially malicious activity.

These observations indicated suspicious behavior but did not independently prove successful exploitation.

### 6. Investigate Additional Infrastructure

I also examined traffic from other IP addresses to determine whether additional infrastructure might be associated with suspicious activity.

One IP of interest was:

**`18.201.29.183`**

The HTTP logs included a sequence involving file creation and retrieval:

```text
GET /index.jsp
PUT /check.txt
GET /check.txt
```

The `PUT` request returned an HTTP `201 Created` response, and the subsequent retrieval returned `200 OK`.

**Finding:** The sequence demonstrated file creation and retrieval activity worth investigating.

**Security relevance:** Unexpected file-upload functionality can create security risks when not properly restricted or monitored.

This investigation helped me practice examining HTTP methods, analyzing timestamps, and connecting related requests.

### 7. Investigate Session Cookie Activity

The investigation also involved identifying a session cookie associated with the Java web application.

```spl
index=main sourcetype="stream:http" "JSESSIONID"
| table _time src_ip http_method uri_path
| head 20
```

**Finding:** `JSESSIONID`

`JSESSIONID` is commonly used by Java web applications to associate HTTP requests with user sessions.

Session identifiers are security-sensitive because attackers may attempt to steal, manipulate, or misuse them.

**What I learned:** Web security investigations often require understanding both network requests and application session management.

The presence of a session cookie alone does not establish that session hijacking occurred.

### 8. Examine Server-Side Activity

To better understand the relationship between web requests and operating system behavior, I also explored Linux audit events and Apache Tomcat runtime logs.

```spl
index=main sourcetype="auditd:laurel:syscall" "EXECVE"
| spath path=EXECVE.ARGV{} output=args
| eval command=mvjoin(args," ")
| table _time command
```

This allowed me to examine recorded command-line arguments and process execution events.

I also investigated Tomcat exceptions involving Java session handling.

Although some of these investigations remained unresolved during the competition, they gave me additional practice exploring host-level telemetry and correlating different security data sources.

**Skills practiced:** Linux audit analysis, process investigation, application log analysis, and investigative troubleshooting.

---

## Competition Results

I successfully completed six challenges in Scenario 1.

| Challenge | Challenge Name | Points Earned |
|---|---|---:|
| #101 | The Foray Begins | 188 |
| #102 | I've Got a Game Name, Yes I Do! | 185 |
| #103 | We Are All Players | 440 |
| #104 | Some Are Bad Players | 445 |
| #106 | It's All About the Angle | 415 |
| #107 | The Files Are Inside the Computer | 440 |
| **Total** | **6 Correct Challenges** | **2,113** |

The event required analyzing evidence and submitting answers under time pressure. These results reflect the questions I successfully answered, not an overall competition ranking.

---

## Technical Skills Demonstrated

| Skill | Practical Application |
|---|---|
| Security Operations Center Analysis | Investigated simulated security events using a SIEM |
| Threat Hunting | Identified suspicious web requests and unusual activity patterns |
| Splunk SPL | Applied search, filtering, aggregation, and statistical commands |
| Log Analysis | Interpreted HTTP, Apache Tomcat, and Linux audit logs |
| Network Security | Analyzed IP addresses, HTTP methods, URL paths, and network activity |
| Web Application Security | Investigated session cookies and file-related HTTP requests |
| Incident Investigation | Developed findings from timestamped security events |
| Analytical Thinking | Evaluated competing explanations and investigated uncertain evidence |
| Technical Documentation | Recorded methods, queries, and findings in a structured report |

---

## Challenges and Lessons Learned

This competition was a valuable hands-on learning experience because it required me to apply technical knowledge in a time-constrained environment.

Some of the biggest lessons I took away were:

**Understanding the data comes first.** Identifying available sources helped me determine where to search for different types of security events.

**Normal versus suspicious activity matters.** Learning how users interacted with the application made unusual requests easier to recognize.

**Correlating multiple log sources provides better context.** HTTP logs revealed network activity, while Apache Tomcat and Linux audit logs provided additional insight into application and host behavior.

**Evidence matters more than assumptions.** Suspicious activity does not always establish a successful compromise. Investigative conclusions should reflect what the available logs actually support.

**Time management is an important technical skill.** Some questions required more investigation than anticipated, reinforcing the importance of prioritizing tasks during a timed competition.

**Documentation strengthens technical communication.** Explaining the purpose of SPL queries and the meaning of their results helped reinforce my understanding of security analysis.

---

## Career Relevance

My long-term technical interests include network engineering, cloud infrastructure, and cybersecurity.

Participating in Cisco Splunk BOTS V10 gave me practical exposure to how security analysts investigate network and application activity using centralized logging and search tools.

This experience strengthened my interest in developing skills related to:

- Security Operations Center (SOC) analysis
- Network security monitoring
- Threat detection and investigation
- Cloud and infrastructure security
- Incident investigation and response

I plan to continue building my technical experience through cybersecurity competitions, hands-on labs, academic projects, and professional development.

---

## Final Reflection

Cisco Splunk BOTS V10 challenged me to apply cybersecurity knowledge in a competitive environment rather than simply study concepts in a classroom.

The experience helped me become more comfortable using Splunk, analyzing security logs, investigating suspicious activity, and working through unfamiliar technical problems.

Most importantly, it reinforced the value of continuous learning, hands-on practice, and evidence-based analysis as I prepare for opportunities in IT infrastructure, networking, and cybersecurity.

---

*This repository documents my participation in an authorized, simulated cybersecurity competition. The investigation findings reflect the available evidence and my learning experience, without claiming completion of the entire event or successful exploitation beyond what was established.*

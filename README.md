# Cisco Splunk BOTS V10 | Blue Team SOC Investigation

**Cybersecurity Competition | Cal Poly Pomona | October 29, 2026**

## Overview

I participated in the **Cisco Splunk Boss of the SOC (BOTS) V10 competition**, a timed cybersecurity competition where participants investigate simulated cyberattacks using Splunk.

During the competition, I worked on Scenario 1: **Cats and Dawgs**, investigating suspicious web traffic, potential attacker activity, and server-side security events using Splunk Search Processing Language (SPL).

## Competition Results

- **6 challenges answered correctly**
- **2,113 points earned** across those six challenges
- Investigated a simulated attack against a web application
- Analyzed HTTP traffic, Apache Tomcat logs, and Linux audit events

## Tools & Skills

- Splunk and Search Processing Language (SPL)
- Security Operations Center (SOC) investigation
- Threat hunting and log analysis
- HTTP traffic analysis
- Suspicious IP address investigation
- Session-cookie analysis
- Linux audit log analysis

## Investigation Highlights

### 1. Web Server Identification

Used Splunk to analyze web application logs and identify Apache Tomcat as the web server.

### 2. Web Application Discovery

Investigated HTTP requests to identify the application's domain and URL paths.

### 3. Suspicious IP Investigation

Analyzed traffic patterns and identified potentially malicious requests associated with the threat actor.

### 4. Session Cookie Investigation

Examined HTTP requests containing `JSESSIONID`, a session cookie used by Java web applications.

### 5. Security Log Analysis

Reviewed Linux audit events and Apache Tomcat runtime logs to investigate suspicious application behavior.

## Lessons Learned

The competition helped me develop hands-on experience investigating simulated cybersecurity incidents under time pressure. I practiced writing SPL queries, interpreting security events, and correlating evidence from multiple log sources.

## Evidence

This repository will include screenshots of my Splunk searches, investigation results, and completed competition challenges.

*This project documents my participation and investigation process, not a claim of completing or winning the entire competition.*

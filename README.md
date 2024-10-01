# Windows Event Logs: A Comprehensive Guide for Active Directory Penetration Testing

This guide covers essential aspects of utilizing Windows Event Logs for Active Directory Penetration Testing. It includes best practices, step-by-step instructions, and practical exercises to help you identify malicious activities in Windows environments.

---

## Table of Contents
1. [Introduction](#introduction)
2. [Why Windows Event Logs are Critical for Active Directory Penetration Testing](#why-windows-event-logs-are-critical-for-active-directory-penetration-testing)
3. [Key Windows Event IDs for Penetration Testers](#key-windows-event-ids-for-penetration-testers)
4. [Configuring Event Logging](#configuring-event-logging)
5. [Monitoring Authentication Events](#monitoring-authentication-events)
6. [Detecting Privilege Escalation](#detecting-privilege-escalation)
7. [Tracking Lateral Movement](#tracking-lateral-movement)
8. [Detecting Advanced Attacks (Pass-the-Hash, DCSync, Kerberoasting)](#detecting-advanced-attacks-pass-the-hash-dcsync-kerberoasting)
9. [Utilizing Sysmon and ETW for Enhanced Detection](#utilizing-sysmon-and-etw-for-enhanced-detection)
10. [Practical Exercise: Identifying Indicators of Compromise](#practical-exercise-identifying-indicators-of-compromise)
11. [Best Practices for Event Log Monitoring](#best-practices-for-event-log-monitoring)
12. [Additional Resources](#additional-resources)

---

## Introduction

Windows Event Logs offer a wealth of information about system activity and security events in an Active Directory (AD) environment. This guide focuses on leveraging Windows Event Logs for detecting malicious activity during penetration tests. By understanding the importance of key event logs and using proper auditing techniques, you can better detect and investigate attacks such as privilege escalation and lateral movement.

---

## Why Windows Event Logs are Critical for Active Directory Penetration Testing

Windows Event Logs provide detailed insights into system and user activities. These logs serve as one of the most effective ways to detect suspicious actions in an Active Directory environment. They can expose a range of activities, including failed authentication attempts, unauthorized privilege escalations, and lateral movements.

### Key Benefits:
- **Authentication Auditing**: Helps monitor failed and successful login attempts.
- **Privilege Monitoring**: Identifies when privileges are elevated unexpectedly.
- **Attack Detection**: Logs capture known attack techniques like Pass-the-Hash (PtH), Pass-the-Ticket, and DCSync.

---

## Key Windows Event IDs for Penetration Testers

Monitoring specific Event IDs is crucial to identifying suspicious behavior. Below are essential Event IDs:

| Event ID | Description | Relevance for Penetration Testing |
|----------|-------------|-----------------------------------|
| **4624** | Successful Account Logon | Key for detecting suspicious or high-privilege logins. |
| **4625** | Failed Account Logon | Critical for spotting brute force or account enumeration attempts. |
| **4768** | Kerberos TGT Request | Monitor for Kerberos-based attacks, such as ticket abuse. |
| **4769** | Kerberos Service Ticket Request | Useful for detecting Kerberoasting attacks. |
| **4776** | NTLM Authentication Attempt | Important for tracking NTLM-based attacks, including PtH. |
| **4672** | Special Privilege Assigned to New Logon | Crucial for detecting privilege escalation. |
| **4688** | New Process Created | Detect process execution related to malware or suspicious scripts. |
| **4697** | Service Installation Detected | Monitor for unwanted or malicious service installations. |
| **7045** | A Service Was Installed | Can indicate lateral movement or persistence techniques. |

> **2024 Update**: Pay attention to **4768** and **4769** for tracking Kerberoasting, which has become a more frequent attack vector in AD environments.

---

## Configuring Event Logging

Without proper logging configurations, crucial events may not be recorded, making forensic analysis impossible. It’s essential to configure Windows to log the right events for penetration testing and auditing.

### Steps to Configure Advanced Event Logging:

1. Open **Group Policy Management Console**.
2. Navigate to **Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration**.
3. Enable auditing for categories like **Logon/Logoff**, **Account Logon**, **Privilege Use**, and **System Integrity**.
4. Set up **Object Access** to monitor file and folder access, useful for identifying ransomware or data exfiltration attempts.
5. Ensure log retention policies are configured to avoid log overwrites.

> **Pro Tip**: Centralize logs using **Windows Event Forwarding** (WEF) or a SIEM platform to make monitoring across multiple hosts easier.

---

## Monitoring Authentication Events

Monitoring login events, including failed authentication attempts, is key to identifying attacks such as brute force, password spraying, or privilege abuse.

### Steps to Monitor Authentication Events:

1. Open **Event Viewer**.
2. Navigate to **Windows Logs > Security**.
3. Filter logs using Event IDs **4624** (success) and **4625** (failure).
4. Analyze login attempts, especially high-privilege accounts like **Domain Admins**.

### Practical Example:
- Multiple **4625** (failed logins) within seconds from a single IP could indicate a brute force attack.
- Track the origin IP and username to detect any suspicious access attempts.

---

## Detecting Privilege Escalation

Privilege escalation involves attackers gaining higher access rights than intended. Monitoring for **Event ID 4672** helps identify when privileged accounts log in or if privileges are assigned.

### Steps to Detect Privilege Escalation:

1. In **Event Viewer**, filter for Event ID **4672**.
2. Check for high-privilege accounts like **Domain Admin** or **Enterprise Admin** logging in.
3. Investigate if privilege escalation coincides with other suspicious activities (e.g., new processes or file accesses).

### Practical Example:
- An attacker compromises a **Helpdesk** account and elevates privileges to a **Domain Admin**. By correlating **4624** and **4672**, you can track the escalation.

---

## Tracking Lateral Movement

Attackers often move laterally across systems to access high-value targets. Event IDs **4624** and **4648** can help track this behavior.

### Indicators of Lateral Movement:
- Same user account logging into multiple systems within a short timeframe.
- Unusual logon types like **Type 3** (network logon) on multiple devices.
- Remote desktop or service installation activity (Event ID **7045**).

### Practical Example:
- Follow the sequence of **4624** (successful login) events across multiple servers to trace lateral movement.

---

## Detecting Advanced Attacks (Pass-the-Hash, DCSync, Kerberoasting)

Several advanced attack techniques target AD environments. Monitoring specific event logs can help detect them early.

### Pass-the-Hash Detection:
- Monitor for **Event ID 4624** with **Logon Type 3** (network logon) using **NTLM** authentication.
- Investigate high-privilege accounts using NTLM logins from unexpected locations.

### DCSync Detection:
- DCSync attacks can steal password hashes from domain controllers. Look for Event ID **4662**, which records permission changes to directory services objects.

### Kerberoasting Detection:
- **Event ID 4769** indicates a request for Kerberos service tickets, often a sign of Kerberoasting. Investigate large numbers of service ticket requests.

---

## Utilizing Sysmon and ETW for Enhanced Detection

To deepen your monitoring capabilities, consider implementing **Sysmon** and utilizing **Event Tracing for Windows (ETW)**.

### What is Sysmon?
**Sysmon** is a Windows system service and device driver that logs system activity to the Windows Event Log. It provides detailed information about process creations, network connections, and other activities, making it invaluable for threat detection.

### Key Sysmon Event IDs:
| Event ID | Description | Relevance |
|----------|-------------|-----------|
| **1** | Process Creation | Identifies new processes that can indicate malware execution. |
| **3** | Network Connection | Tracks outbound network connections, essential for detecting command-and-control activities. |
| **10** | Process Access | Monitors which processes are accessing other processes, useful for detecting process injection. |

### Event Tracing for Windows (ETW)
ETW allows for high-performance logging of events in Windows. It enables developers and system administrators to capture detailed information about system activity.

#### Advantages of ETW:
- **Low Overhead**: Captures events with minimal performance impact.
- **Comprehensive Data**: Provides granular data that can be used for in-depth analysis.
- **Real-Time Monitoring**: Enables real-time event tracking and analysis.

### Implementation Tips:
- **Integrate Sysmon**: Deploy Sysmon on critical systems and configure it to capture relevant events.
- **Leverage ETW**: Use ETW in conjunction with Sysmon to gain insights into application performance and security events.

---

## Practical Exercise: Identifying Indicators of Compromise

### Scenario:
- The **Domain Admin** account has been compromised, and lateral movement is underway. Your task is to identify the attack using Windows Event Logs.

### Steps:
1. Filter for **4624** (logon) and **4672** (privilege escalation) events for the **Domain Admin** account.
2. Correlate the timestamps with other systems, looking for multiple logons from different locations.
3. Investigate any NTLM logon activity, especially if **Logon Type 3** is involved.
4. Review Sysmon logs for **Event ID 1** (Process Creation) to identify any unusual processes spawned around the same timeframe.
5. Analyze **Event ID 3** (Network Connection) to track outbound connections that may indicate communication with a command-and-control server.

> **Goal**: Trace the attacker’s movements and identify potential lateral movement and privilege escalation, utilizing both Windows Event Logs and Sysmon data.

---

## Best Practices for Event Log Monitoring

1. **Centralize Logs**: Use a SIEM or Windows Event Forwarding to collect and analyze logs across the entire domain.
2. **Enable Relevant Auditing**: Ensure critical categories like **Account Logon**, **Privilege Use**, and **Process Creation** are audited.
3. **Set Alerts**: Configure real-time alerts for suspicious events, such as repeated failed logons or unexpected privilege escalations.
4. **Regular Reviews**: Perform periodic log reviews to identify patterns and anomalies that automated tools may miss.
5. **Implement Sysmon**: Use Sysmon for enhanced visibility into system processes and network activity. Properly configure Sysmon to capture relevant event IDs for better monitoring.
6. **Utilize ETW**: Leverage ETW for real-time tracking of application performance and security events, ensuring low overhead on system performance.

---

## Additional Resources

- [Windows Event Log Reference](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log-reference)
- [Securing Active Directory: Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [MITRE ATT&CK Framework: Active Directory Techniques](https://attack.mitre.org/)
- [Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Understanding Event Tracing for Windows (ETW)](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)

---

### Contributions

Feel free to contribute, report issues, or submit feature requests via GitHub. Your feedback helps improve this guide and serves the broader cybersecurity community.

# soar-edr-incident-response
SOAR + EDR lab project using LimaCharlie and Tines to detect password recovery tools, send real-time alerts, and automate host isolation.

## 🛡️ Project Overview
SOAR EDR Incident Response Project demonstrates how to integrate LimaCharlie (EDR) and Tines (SOAR) to automatically detect and respond to credential dumping attempts on a Windows endpoint. It showcases real-time alerts (Slack + Email), analyst decision prompts, and automated host isolation.

## Skills Learned
- Writing custom EDR detection rules (YAML in LimaCharlie).
- Building SOAR workflows in Tines.
- Automating Slack & Email alerts.
- Integrating EDR with SOAR via APIs.
- Host isolation and containment workflows.

## Tools Used
- VMware Workstation
- Windows Server 2016
- LimaCharlie (EDR)
- Tines (SOAR)
- Slack & Email integrations
  
![Lab Setup](screenshots/soar_edr_ir_arch.png)

## 🖥️ Lab Architecture & Workflow

Shows how suspicious activity on the endpoint is detected, forwarded, and responded to:

1. Endpoint (Windows Server VM) → The simulated attacker runs LaZagne, a password recovery tool.
2. LimaCharlie (EDR) → Detects the suspicious process execution based on detection rules
3. Tines (SOAR) → Receives the alert from LimaCharlie through a webhook integration.
4. Slack & Email → Tines automatically notifies the SOC team in real time.
5. Analyst Decision → Tines prompts the analyst to decide whether the endpoint should be isolated.
6. Host Isolation → If approved, Tines calls the LimaCharlie API to quarantine the endpoint. A confirmation is sent back to Slack.

![Workflow](screenshots/soar_edr_ir_workflow.png)
   
## ⚙️ Setup & Configuration

- Deployed Windows Server VM and installed LimaCharlie agent.

- Download the appropriate Windows LimaCharlie sensor from the LC console.
![Sensor Download](screenshots/LC_sensor_download.png)

- Generated an installation key in LimaCharlie.
![Installation Keys](screenshots/LC_Installation_keys.png)

- Installed the agent on the Windows VM using PowerShell.
![Sensor Download & Keys](screenshots/vm_sensor_download_sensor_keys.png) 

- Verified the sensor check-in under LimaCharlie → Sensors.
  
  ![Sensor Connection](screenshots/sensor_connect.png) 

- Configured Slack + Email integrations in Tines.
- Built LimaCharlie → Tines webhook connection.

## 🔍 Detection Rules (LimaCharlie)
To detect suspicious credential dumping activity, I created a custom detection rule in LimaCharlie targeting the execution of LaZagne.

### Detection Logic

This rule applies to Windows endpoints and triggers on both `NEW_PROCESS` and `EXISTING_PROCESS` events.
It generates an alert if any of the following conditions are met:
- Process file path ends with `lazagne.exe`
- Command line ends with `all` (a common LaZagne execution flag)
- Command line contains the keyword lazagne
- File hash matches a known LaZagne binary

### Detection Rule (YAML)

```yaml

Dection Rule
```

![Detection Rule](screenshots/vm_sensor_download_sensor_keys.png)


### Detection Response

The detection is configured to generate a report with context, tagged under MITRE ATT&CK – Credential Access.

```yaml

- action: report
  metadata:
    author: ndean
    description: Detects LaZagne (SOAR-EDR Tool)
    falsepositives:
      - a lot
    level: medium
    tags:
      - attack.credential_access
  name: MyDFIR - HackTool - Lazagne (SOAR-EDR)
```

![Dtection Resonse](screenshots/vm_sensor_download_sensor_keys.png)

## ⚡ Tines SOAR Story

Insert flow diagram.
Explain major steps:

1. Webhook receives detection.
2. Slack + Email notifications.
3. Analyst prompt for isolation decision.
4. API call to LimaCharlie if approved.
📸 [Insert screenshot of Tines flow]

⚡ Tines SOAR Story

## 📸 Demonstration Timeline (Incident Response in Action)

Step-by-step sequence:

1. Suspicious Tool Execution (Trigger Event)
- LaZagne executed on endpoint.
  📸 [Insert screenshot of LaZagne execution]
2. Detection Raised (LimaCharlie → Tines)
- Alert generated and forwarded.
📸 [Insert screenshot of Slack alert]
📸 [Insert screenshot of Email alert]
3. Analyst Prompted
- Analyst receives isolation decision form.
📸 [Insert screenshot of Tines user prompt]
4. Isolation Executed
- Endpoint quarantined, confirmation posted.
📸 [Insert screenshot of Slack isolation message]
📸 [Insert screenshot of LC console showing Isolated]

## 🔮 Next Steps

Add detection coverage for other credential theft tools.

Expand SOAR workflows to include ServiceNow/Jira ticketing.

Enrich alerts with MITRE ATT&CK mappings and threat intel.

## 📝 Report

Short narrative summary — written like a mini SOC incident report.
Example: This lab demonstrated that integrating LimaCharlie with Tines provides effective automated response to credential-dumping activity. Detections flowed seamlessly into SOAR, notifications reached analysts, and automated containment reduced MTTR.

## 📚 References

LimaCharlie Documentation

Tines Documentation

@MyDFIR YouTube Walkthrough

## 🏁 Conclusion
Summarize the project’s significance.


## 🧩 Skills Demonstrated

Threat detection & alerting (EDR).

Workflow automation (SOAR).

Incident triage & containment.

API-driven integration.

SOC analyst decision-making.

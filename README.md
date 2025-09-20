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

![Sensor Download](screenshots/LC_sensor_download.png)
Copy the sensor download link that matches the machine type to 
![Intallation Keys](screenshots/LC_Installation_keys.png)
![Intallation Keys](screenshots/vm_sensor_download_sensor_keys.png)  
- Configured Slack + Email integrations in Tines.
- Built LimaCharlie → Tines webhook connection.


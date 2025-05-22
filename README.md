# Snort-Lab

## Objective

The Snort lab is designed to install and configure Snort 3 IDS on a virtual network, analyze malicious PCAP files, and create a basic signature.

### Skills Learned

- Snort 3 Deployment: Installed and configured Snort 3 IDS within a virtualized network environment to monitor and analyze network traffic.

- Intrusion Detection Configuration: Tuned Snort settings and modules to optimize detection capabilities for various threat scenarios.

- PCAP Analysis: Analyzed malicious PCAP files to identify indicators of compromise and understand attack behaviors.

- Signature Development: Created basic Snort signatures to detect specific malicious patterns observed in network traffic.

- Network Forensics: Gained foundational experience in interpreting packet-level data for threat investigation and response.

- Rule Testing & Validation: Tested custom Snort rules against known malicious traffic to ensure accurate detection and minimize false positives.

### Tools Used

- Snort 3: IDS for real-time traffic analysis and packet logging
- PulledPork: for managing and updating Snort rules and signatures
- VirtualBox: to build and manage the lab network environment
- Ubuntu Server: used as the host for Snort
- PCAP Files: Malicious network capture files used to simulate attack scenarios and test detection logic

## Steps
I follwed along with the <a href="https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/012/147/original/Snort_3.1.8.0_on_Ubuntu_18_and_20.pdf">Snort on Ubuntu guide written by Noah Dietrich</a> for the installation and configuration of Snort 3 on my Ubuntu Server.

![image](https://github.com/user-attachments/assets/83a5ffb7-c817-4209-a5fb-600b3045991b)

To test that Snort is working and generating alerts, I created a custom rule to detect ICMP traffic. 

![image](https://github.com/user-attachments/assets/52edcd2b-781d-4da5-97eb-b526d4ae8f94)

- alert: Tells Snort to alert if it encounters any of the follwing traffic
- icmp: Specifies traffic to icmp
- any any -> any any: Source address and source port to destination address and destination port
- msg: If snort detects the following traffic the message "ICMP Detected" will display
- sid: idectification number for the custom alert

To test the new alert I start running snort then use a different machine to ping the snort server.

![image](https://github.com/user-attachments/assets/25478fe3-ac26-40c1-a4c5-d9c69c1c1b78)

I want to expand my ruleset by installing a tool called PulledPork.

![image](https://github.com/user-attachments/assets/02c28c42-87a8-413d-be3c-c79725b060b1)

After installing PulledPork, I can now use the Snort IDS and generate a signature to make investigating suspicious PCAPs a bit easier.

I downloaded a PCAP from <a href="https://malware-traffic-analysis.net/index.html">Malware-Traffic-Analysis.net</a> and feed it into snort to see what it brings up.

After sorting the data this is the result.

![MalwareTrafficAnalysisSnort](https://github.com/user-attachments/assets/e443e2be-92bd-4f8e-8cf3-c5d83a1be934)

"MALWARE-OTHER" alerted towards the bottom.

If I use grep to investigate further, I can find more detail about the malware found.

![image](https://github.com/user-attachments/assets/a4dc0f26-4d61-44d4-acdd-f85ed85be76a)

Results show some more detail about the malware signature including the source ip address. 

# NVD_Auto_Score
## Auto Score NVD CVEs Using GPT-4

Given a CVE, and using only limited information an NVD analyst would have to review and rate a CVE, this AI script will:
* Take the CVE Description and Reference URLs to create a detailed description
* Rate each CVSS 3.1 attribute
* Use those attributes to include the CVSS 3.1 score



## Example Output
Here is an example output for CVE-2021-44228 (the Log4Shell Vulnerability):

Vulnerability Summary:
The Apache Log4j library is suffering from a 0-day exploit, tracked as CVE-2021-44228, allowing remote code execution without user interaction. The vulnerability can be exploited by crafting a specially structured input, which can lead to arbitrary code execution when the log4j library performs the lookup for logging. This vulnerability affects versions 2.0-beta9 to 2.14.1 and has severe impacts due to the widespread use of this library in various applications.

1. Attack Vector: Network. The attacker can exploit this vulnerability remotely over a network.

2. Attack Complexity: Low. The knowledge and resources required for this attack is minimal. 

3. Privilege Required: None. No special privileges are needed to exploit this vulnerability.

4. User Interaction: None. No user interaction is required for the exploit to be effective.

5. Scope: Changing. This vulnerability can affect resources beyond the immediate scope of the vulnerable component.

6. Confidentiality Impact: High. An attacker can execute arbitrary code on the target system and access sensitive data.

7. Integrity Impact: High. The execution of arbitrary code allows an attacker to modify all types of data within the system.

8. Availability Impact: High. If successful, the exploit can cause the application using the Log4j library to crash, thus denying service to legitimate users.

9. CWE: This vulnerability can be classified as CWE-20, which stands for "Improper Input Validation".

Based on severity of the vulnerability and the widespread use of Log4j, organizations should prioritize updating their Apache Log4j library to a patched version as soon as possible. It's also recommended that companies update their intrusion detection systems (IDS) and firewall rules to catch attempts to exploit this vulnerability. Regardless of the network exposure, this vulnerability presents an imminent threat to both public and internal networks due to its potential for arbitrary code execution capabilities.

CVSS 3.1 Base Score: 10.0


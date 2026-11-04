# **Blue Team Challenge: Encrypted Log Investigation & Attack Detection**

## **Overview**

You are part of a Blue Team responsible for monitoring and securing a web application.

A suspicious activity log has been provided to you, but the log has been encrypted using a **classical substitution-based cipher**. Your task is to recover the original log, investigate the traffic, identify malicious activity, and build an automated detection script.

This challenge tests your ability to:

* Analyze unfamiliar data  
* Reverse-engineer a simple encryption scheme  
* Perform log analysis  
* Identify common web attacks  
* Write a Bash-based detection tool  
* Produce a clear incident report

---

# **Scenario**

A web server has generated an access log containing normal user activity as well as several malicious requests.

However, the log was encrypted before being provided to you.

Your job is to:

1. Decrypt the log.  
2. Analyze the recovered traffic.  
3. Identify **three distinct attacks**.  
4. Determine the attacker IP, timestamps, and number of malicious requests.  
5. Write an automated detection script.  
6. Prepare a short incident report containing your findings and recommended actions.

---

# **Part 1 — Decrypt the Log**

You will receive a file named:

access.log.enc

The file is encrypted using a **Vigenère cipher**.

You are given the following hints:

### **Hint 1**

The encryption uses a **repeating key**.

### **Hint 2**

Only **alphabetic characters (A–Z and a–z)** are encrypted.

Numbers, spaces, punctuation, `/`, `.`, `'`, `-`, `?`, `=` and other special characters remain unchanged.

### **Hint 3**

The cipher uses the standard 26-letter alphabet:

A B C D E ... X Y Z

The encryption follows the standard Vigenère cipher.

For example, if a plaintext letter is `A` and the corresponding key letter represents a shift of `C`, the encrypted letter becomes `C`.

### **Hint 4**

The encryption key is:

**MAYDAY**

### **Important**

The key **resets at the beginning of every line**.

After decrypting the file, save the recovered log as:

access.log

Do not modify the contents of the decrypted log.

---

# **Part 2 — Investigate the Log**

Analyze `access.log` and identify the following three types of attacks:

### **1\. Brute-Force Login Attack**

Consider an IP address to be conducting a brute-force attack if it generates:

5 or more HTTP 401 responses

Your investigation should determine:

* Attacker IP address  
* First failed-login timestamp  
* Last failed-login timestamp  
* Total number of failed login attempts

---

### **2\. SQL Injection**

Identify requests containing any of the following patterns:

DROP TABLE  
OR 1=1  
OR '1'='1'

Determine:

* Attacker IP address  
* First SQL injection timestamp  
* Last SQL injection timestamp  
* Total number of SQL injection attempts

The matching should be performed on the **decrypted log contents**.

---

### **3\. Directory Traversal**

Identify requests containing:

../

Determine:

* Attacker IP address  
* First directory traversal timestamp  
* Last directory traversal timestamp  
* Total number of directory traversal attempts

**Hint:** Use regex to deal with this.

---

# **Part 3 — Create an Automated Detection Script**

Create a Python script named:

./detect.sh

The script must accept the encrypted log file as its argument:

./detect.sh access.log.enc

The script should:

1. Accept the encrypted file as input.  
2. Decrypt the file internally.  
3. Analyze the decrypted contents.  
4. Detect all three attack types.  
5. Print an alert for every detected attack.  
6. Exit with the appropriate status code.

The script **must not require the user to manually decrypt the file first**.

---

## **Expected Alert Format**

Your output should follow this general format:

\[ALERT\] Brute force from \<IP\> (\<COUNT\> failed logins)  
\[ALERT\] SQL injection from \<IP\> (\<COUNT\> attempts)  
\[ALERT\] Directory traversal from \<IP\> (\<COUNT\> attempts)

For example:

\[ALERT\] Brute force from 203.0.113.42 (9 failed logins)  
\[ALERT\] SQL injection from 51.77.72.9 (6 attempts)  
\[ALERT\] Directory traversal from 88.198.50.20 (7 attempts)

Your script must **calculate these values dynamically**.

Do **not** hard-code the IP addresses or attack counts.

---

# **Exit Codes**

Your script must follow these rules:

### **If at least one attack is detected:**

exit 1

### **If no attacks are detected:**

exit 0

This allows the script to be used in an automated monitoring system.

For example:

./detect.sh access.log.enc  
echo \$?  
---

# **Part 4 — Investigation Findings**

Create a file named:

findings.txt

The file should contain your investigation results.

Use the following format:

BLUE TEAM INVESTIGATION FINDINGS

1\. Brute Force Attack  
Attacker IP:  
First Attempt:  
Last Attempt:  
Total Attempts:

2\. SQL Injection  
Attacker IP:  
First Attempt:  
Last Attempt:  
Total Attempts:

3\. Directory Traversal  
Attacker IP:  
First Attempt:  
Last Attempt:  
Total Attempts:

All values must be obtained from your analysis of the decrypted log.

---

# **Part 5 — Incident Report**

Create a Report file named:

report.txt

The report should contain the following sections.

## **1\. Executive Summary**

Write **one paragraph** summarizing:

* What happened  
* How many attack types were identified  
* Which parts of the application were targeted  
* The overall severity of the incident

---

## **2\. Attack Summary**

Create a table (a csv file would also do) using the following structure:

| Attack Type | Attacker IP | First Seen | Last Seen | Attempts |
| ----- | ----- | ----- | ----- | ----- |
| Brute Force |  |  |  |  |
| SQL Injection |  |  |  |  |
| Directory Traversal |  |  |  |  |

---

## **3\. Recommended Actions**

Provide **one recommended defensive action for each attack**.

---

# **Part 6 — Validation**

Your solution should be tested against the provided encrypted log.

Run:

chmod \+x detect.sh  
./detect.sh access.log.enc

The script should identify all malicious activity.

Also verify the exit code:

echo \$?

The expected result when attacks are detected is:

1  
---

# **Deliverables**

Submit the following files:

access.log  
detect.sh  
findings.txt  
report.txt

Your final directory should look like:

submission/  
├── access.log  
├── detect.sh  
├── findings.txt  
└── report.txt  
---

# **Constraints**

1. The encrypted input file must be accepted by `detect.sh`.  
2. The script must perform the decryption itself.  
3. Do not manually edit the decrypted log to remove or alter entries.  
4. Do not hard-code attacker IP addresses.  
5. Do not hard-code attack counts.  
6. The detection logic should work based on the defined rules.  
7. The script must correctly return `0` for a clean log and `1` when an attack is detected.  
8. Your findings must be based on evidence present in the log.  
9. Keep the solution reproducible: another person should be able to run your script against the provided encrypted log and obtain the same results.

---

# **Bonus Challenges**

For participants looking for an additional challenge:

### **Bonus 1 — Generalized Decryption**

Modify your script so that the Vigenère key is supplied as an argument:

./detect.sh access.log.enc MAYDAY

instead of being embedded directly into the script.

### **Bonus 2 — Multiple Attackers**

Modify the detector so that it reports **every IP** satisfying an attack condition rather than assuming there is only one attacker per attack type.

### **Bonus 3 — Better Detection**

Extend the detector to identify suspicious activity beyond the three specified attacks.

Examples include:

* Repeated `403` responses  
* Suspicious administrative access  
* Unusual login behavior  
* Requests targeting sensitive files  
* Multiple attack types originating from the same IP

### **Bonus 4 — SOC-Style Output**

Add timestamps and severity levels to the alerts, for example:

\[2024-03-15 09:22:45\] \[HIGH\] Brute force detected from 203.0.113.42  
---


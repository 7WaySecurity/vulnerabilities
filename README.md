# vulnerabilities

CVE-ID
CVE-2024-27574

CVSSCORE 7.5 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N



DESCRIPTION:

SQL injection vulnerability in Trainme Academy Ichin v.1.3.2


A SQL injection vulnerability is identified in a lack of proper validation in data entry in one of the fields of the course management system. This allows an attacker to inject and execute SQL queries, compromising the security of over 200 databases and granting unauthorized access to sensitive information.

REFERENCES:
https://owasp.org/Top10/es/A03_2021-Injection/ 

https://capec.mitre.org/data/definitions/66.html




Blind SQL injection is evident
![](https://github.com/7WaySecurity/vulnerabilities/blob/main/Screenshot.png)


The databases are evident.
![](https://github.com/7WaySecurity/vulnerabilities/blob/main/Screenshot1.png)


Access to a database containing the access information of users including the administrator is evident.
![](https://github.com/7WaySecurity/vulnerabilities/blob/main/Screenshot2.png)

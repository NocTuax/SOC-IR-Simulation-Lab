"""Sample Wazuh alerts for testing"""

BRUTE_FORCE_ALERT = {
    "id": "1621941234.12345",
    "rule": {
        "id": 5763,
        "level": 10,
        "description": "sshd: brute force trying to get access to the system"
    },
    "data": {
        "srcip": "192.168.1.29",
        "dstip": "192.168.1.17",
    },
    "full_log": "May 25 18:42:33 jh-server sshd[8395]: Failed password for root from 192.168.1.29 port 47770 ssh2",
    "agent": {"id": "001", "name": "JH"}
}

MALWARE_ALERT = {
    "id": "1621941234.12346",
    "rule": {
        "id": 554,
        "level": 5,
        "description": "File added to the system"
    },
    "data": {
        "srcip": "192.168.1.17",
        "dstip": None,
    },
    "full_log": "File '/tmp/c2_beacon.sh' added to the system.",
    "agent": {"id": "001", "name": "JH"}
}

SQLI_ALERT = {
    "id": "1621941234.12347",
    "rule": {
        "id": 100040,
        "level": 10,
        "description": "SQL Injection pattern detected"
    },
    "data": {
        "srcip": "192.168.1.29",
        "dstip": "192.168.1.17",
    },
    "full_log": "POST /vulnerabilities/sqli/ - Payload: id=1' OR '1'='1",
    "agent": {"id": "001", "name": "JH"}
}

SAMPLE_ALERTS = {
    "brute_force": BRUTE_FORCE_ALERT,
    "malware": MALWARE_ALERT,
    "sqli": SQLI_ALERT,
}
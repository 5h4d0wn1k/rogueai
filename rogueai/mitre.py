MAPPING = {
    "port_probe": "T1046 Network Service Discovery",
    "dyn_sqli": "T1190 Exploit Public-Facing Application",
    "xss": "T1059 Command and Scripting Interpreter",
    "mqtt_subs": "T1071 Application Layer Protocol",
    "cred_spray": "T1110.001 Password Guessing",
    "vault_read": "T1552.001 Credentials in Files",
    "write_note": "T1588.002 Tool",
    "read_plan": "Meta",
    "query_state": "Meta",
}

USED_BY = ["T1588.002 Tool"]


def technique_for(tool):
    return MAPPING.get(tool, "Unmapped")
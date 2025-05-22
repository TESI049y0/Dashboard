def controleer_compliance(scan_data):
    """
    Analyseer scanresultaten op basis van ISO27001-richtlijnen.
    Retourneert lijst van non-compliant regels.
    """
    non_compliant = []

    for host in scan_data:
        ip = host.get('ip')
        for port in host.get('ports', []):
            poort = port.get('poort')
            service = port.get('service')
            status = port.get('status')

            if status == 'open' and service == 'telnet':
                non_compliant.append({
                    'ip': ip,
                    'poort': poort,
                    'reden': 'Telnet is verboden onder ISO27001'
                })

    return non_compliant

import scapy.all as scapy

# Dicionários globais para fácil alcance de dados
TCP_MAP = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 23: "Telnet", 25 : "SMTP", 110 : "POP3" } # porta: protocolo(relacionado com essa porta)
UDP_MAP = {53: "DNS", 67: "DHCP", 68: "DHCP", 546: "DHCPv6", 547: "DHCPv6", 443: "QUIC/HTTPS", 123 : "NTP", 1900 : "SSDP"}

def get_detailed_info(pkt):
    details = [] 
    app_proto = None
    
    # 1. Identificação do Protocolo de Aplicação (para a Stack)
    # Para o dicionário do TCP (TCP_MAP)
    if pkt.haslayer(scapy.TCP):
        sport, dport = pkt[scapy.TCP].sport, pkt[scapy.TCP].dport # Vai ver as portas de origem e destino
        app_proto = TCP_MAP.get(dport, TCP_MAP.get(sport, "TCP")) # Verifica se existem no dicionário
        # Reforço HTTP 
        if pkt.haslayer(scapy.Raw):
            payload = pkt[scapy.Raw].load.decode(errors='ignore')
            if any(kw in payload for kw in ["GET ", "POST ", "HTTP/1."]):
                app_proto = "HTTP"

    # Para o dicionário do UDP (UDP_MAP)         
    elif pkt.haslayer(scapy.UDP):
        sport, dport = pkt[scapy.UDP].sport, pkt[scapy.UDP].dport # Vai ver as portas de origem e destino
        app_proto = UDP_MAP.get(dport, UDP_MAP.get(sport, "UDP")) # Verifica se existem no dicionário
        if pkt.haslayer(scapy.DNS): app_proto = "DNS" # Identificar DNS
        elif pkt.haslayer(scapy.DHCP) or pkt.haslayer(scapy.DHCP6):  # Identificar DHCP (seja IPv4 ou IPv6)
            app_proto = "DHCPv6" if pkt.haslayer(scapy.DHCP6) else "DHCP"

    # 2. Construção da Stack
    stack = []
    IGNORE_LAYERS = ["Padding", "Trailer", "Raw"] # Para ficar com a stack mais limpa
    temp_pkt = pkt
    while temp_pkt:
        name = temp_pkt.name
        if name == "Raw" and app_proto and app_proto not in ["TCP", "UDP"]: # Se for de uma layer diferente o scapy não permite identificar o protocolo(escreve RAW)
            stack.append(app_proto) # Se esse protocolo existir e não for TCP ou UDP, escreve o nome acima identificado
        elif (name not in IGNORE_LAYERS): # Se não for alguns dos supostos layers para ignorar ele acrescenta à stack o nome do protocolo
                stack.append(name)
        
        if not temp_pkt.payload and app_proto and app_proto not in ["TCP", "UDP"]: # Garante que protocolos detetados sem Payload também aparecem na stack (ex: ACKs de HTTP)
            if app_proto not in stack: 
                stack.append(app_proto)

        temp_pkt = temp_pkt.payload

    details.append(f"Stack: {' -> '.join(stack)}")
    details.append("-" * 30)

    # -- Identificação dos vários protocolos divididos pelas suas camadas pertencentes ---
    # --- Camada 2: Data Link Ethernet ---
    if pkt.haslayer(scapy.Ether):
        details.append(f"MAC Origin: {pkt[scapy.Ether].src}")
        details.append(f"MAC Destination: {pkt[scapy.Ether].dst}")
            
    # --- Camada 3: Rede IP, IPv6 ou ARP ---
    is_frag = False
    if pkt.haslayer(scapy.IP):
        ip_layer = pkt[scapy.IP]
        details.append(f"IP Origin: {ip_layer.src}")
        details.append(f"IP Destination: {ip_layer.dst}")
        details.append(f"TTL: {ip_layer.ttl}")

        # --- Detalhes de Fragmentação ---
        # id: Identificador único para o conjunto de fragmentos
        # flags: MF (More Fragments), DF (Don't Fragment)
        # frag: Offset (posição do fragmento no pacote original)

        frag_id = ip_layer.id
        frag_offset = ip_layer.frag  # Este valor deve ser multiplicado por 8 para obter o offset em bytes
        flags = ip_layer.flags
        status = "---"
        
        # Tradução das Flags para algo que se entenda
        flag_list = []
        if flags & 0x02: 
            flag_list.append("(Don't Fragment)")
        if flags & 0x01: 
            flag_list.append("(More Fragments)") # Se tiver a flag MF, é indicado que é fragmentado(is_frag) 
            status = "Middle Fragment" if frag_offset > 0 else "First Fragment" # verifica se é o primeiro pacote ou intermédio
            is_frag = True
        elif frag_offset > 0:
            status = "Last Fragment" # Só pode ser o último pacote fragmentado
            is_frag = True
        if flags & 0x00: flag_list.append("(Reserved)") # Esta flag não possui muita importância(normalmente 0)
        
        flags_str = ", ".join(flag_list) if flag_list else "None"
        if is_frag:
            details.append(f"Fragment ID: {frag_id}")
            details.append(f"Fragment Offset: {frag_offset} ({frag_offset * 8} bytes)")
            details.append(f"Frag status: {status}") 
            details.append(f"IP Flags: {flags} {flags_str}")

            if frag_offset > 0:
                app_proto = f"IP fragment (ID : {frag_id})"

        else: details.append("Not Fragmented")

    elif pkt.haslayer(scapy.IPv6):
        details.append(f"IPv6 Origin: {pkt[scapy.IPv6].src}")
        details.append(f"IPv6 Destination: {pkt[scapy.IPv6].dst}")
        details.append(f"Hop Limit: {pkt[scapy.IPv6].hlim}")
    elif pkt.haslayer(scapy.ARP):
        details.append(f"Protocol: ARP ({'Request (Who has)' if pkt[scapy.ARP].op == 1 else 'Reply (It at)'})")
        details.append(f"Query: {pkt[scapy.ARP].psrc} -> {pkt[scapy.ARP].pdst}")

    # --- Camada 4: Transporte (TCP) ---
    if pkt.haslayer(scapy.TCP):
        sport, dport = pkt[scapy.TCP].sport, pkt[scapy.TCP].dport
        details.append(f"Protocol: {app_proto} (Src Port: {sport} -> Dst Port: {dport})")
        details.append(f"Flags: {pkt[scapy.TCP].flags}")
        if pkt.haslayer(scapy.Raw): details.append("Content: Raw Data")

    # --- Camada 4: Transporte (UDP) ---
    elif pkt.haslayer(scapy.UDP):
        sport, dport = pkt[scapy.UDP].sport, pkt[scapy.UDP].dport
        details.append(f"Protocol: {app_proto} (Src Port: {sport} -> Dst Port: {dport})")
        
        # -- Dentro do UDP ---
        # -- DNS (camada 7 -> Aplicação) ---
        if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qd:
            qname = pkt[scapy.DNS].qd.qname.decode(errors='ignore')
            details.append(f"DNS Query: {qname}")

        # -- DHCP (camada 7 -> Aplicação) ---
        elif pkt.haslayer(scapy.DHCP):
            options = pkt[scapy.DHCP].options
            msg_type = next((opt[1] for opt in options if isinstance(opt, tuple) and opt[0] == 'message-type'), "Unknown")
            dhcp_msgs = {1: "Discover", 2: "Offer", 3: "Request", 5: "ACK"}
            details.append(f"DHCP Message: {dhcp_msgs.get(msg_type, msg_type)}")

    # --- Camada 3 Rede (raramente camada 4 -> Transporte): ICMP / ICMPv6 ---
    elif pkt.haslayer(scapy.ICMP) or pkt.haslayer(scapy.ICMPv6EchoRequest) or pkt.haslayer(scapy.ICMPv6EchoReply):
        is_v6 = pkt.haslayer(scapy.ICMPv6EchoRequest) or pkt.haslayer(scapy.ICMPv6EchoReply) # Verifica de é IPv6
        proto_name = "ICMPv6" if is_v6 else "ICMP"
        
        if is_v6:
            # No IPv6, extraímos o tipo da camada que estiver presente(está divida no scapy por ICMPv6EchoRequest e ICMPv6EchoReply)
            if pkt.haslayer(scapy.ICMPv6EchoRequest):
                tipo = pkt[scapy.ICMPv6EchoRequest].type
            else:
                tipo = pkt[scapy.ICMPv6EchoReply].type
            # Se for o tipo for 128 é Request, 129 é Reply
            msg = "Echo Request" if tipo == 128 else "Echo Reply" if tipo == 129 else f"Type {tipo}"
        else:
            # No IPv4 (ICMP normal)
            tipo = pkt[scapy.ICMP].type
            # Se for o tipo for 8 é Request, 0 é Reply
            msg = "Echo Request" if tipo == 8 else "Echo Reply" if tipo == 0 else "Time Exceeded" if tipo == 11 else f"Type {tipo}"
            
        details.append(f"Protocol: {proto_name} ({msg})")

    elif is_frag and frag_offset > 0:
        details.append(f"Protocol: IPv4 Fragment")

    elif not pkt.haslayer(scapy.ARP):
        details.append("Protocol: Other")

    details.append("-" * 30)
    details.append(f"Total Size: {len(pkt)} bytes")
    return "\n".join(details)

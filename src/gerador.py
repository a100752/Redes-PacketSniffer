import scapy.all as scapy
import sys

# Silenciar avisos internos do Scapy para manter o terminal limpo
scapy.conf.verb = 0

class GeradorPacotes:
    def __init__(self, interface="wlp3s0"):
        self.iface = interface

    def _enviar(self, pkt, nome):
        print(f"[>] A enviar pacote {nome}...")
        # Nota: Usamos sendp pois operamos na Camada 2 (Data Link)
        scapy.sendp(pkt, iface=self.iface, verbose=False)

    # --- Funções de Geração por Protocolo ---

    def gerar_icmp_v4(self):
        pkt = scapy.Ether()/scapy.IP(dst="8.8.8.8")/scapy.ICMP()
        self._enviar(pkt, "ICMPv4 (Ping)")

    def gerar_icmp_v6(self):
        pkt = scapy.Ether()/scapy.IPv6(dst="ff02::1")/scapy.ICMPv6EchoRequest()
        self._enviar(pkt, "ICMPv6 (Ping)")

    def gerar_ip_fragmentado(self):
        # Simula a fragmentação de um pacote ICMP grande em 2 partes
        ip_id = 12345
        payload_parte1 = "A" * 8  # 8 bytes de dados
        payload_parte2 = "B" * 8  # mais 8 bytes
        
        # Fragmento 1: Flag MF (More Fragments) ativa, Offset 0
        frag1 = scapy.Ether()/scapy.IP(dst="8.8.8.8", id=ip_id, frag=0, flags="MF")/scapy.ICMP(type=8, code=0)/payload_parte1
        
        # Fragmento 2: Sem flag MF (último), Offset 2 (unidades de 8 bytes = 16 bytes do cabeçalho ICMP + parte 1)
        # Nota: O offset é medido em blocos de 8 bytes.
        frag2 = scapy.Ether()/scapy.IP(dst="8.8.8.8", id=ip_id, frag=2)/payload_parte2
        
        self._enviar(frag1, "IP Fragmentado (Parte 1/2 - MF=1)")
        self._enviar(frag2, "IP Fragmentado (Parte 2/2 - MF=0)")

    def gerar_dns(self):
        pkt = scapy.Ether()/scapy.IP(dst="8.8.8.8")/scapy.UDP(sport=45000, dport=53)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname="google.com"))
        self._enviar(pkt, "DNS Query")

    def gerar_http(self):
        pkt = scapy.Ether()/scapy.IP(dst="1.1.1.1")/scapy.TCP(sport=50505, dport=80, flags="PA")/scapy.Raw(load="GET /index.html HTTP/1.1\r\nHost: google.com\r\n\r\n")
        self._enviar(pkt, "HTTP GET")

    def gerar_telnet(self):
        pkt = scapy.Ether()/scapy.IP(dst="192.168.1.1")/scapy.TCP(sport=35000, dport=23, flags="PA")/scapy.Raw(load="admin\r\npassword123\r\n")
        self._enviar(pkt, "Telnet (Login Attempt)")

    def gerar_dhcp_v4(self):
        pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.IP(src="0.0.0.0", dst="255.255.255.255")/scapy.UDP(sport=68, dport=67)/scapy.BOOTP(chaddr="00:11:22:33:44:55")/scapy.DHCP(options=[("message-type", "discover"), "end"])
        self._enviar(pkt, "DHCPv4 Discover")

    def gerar_dhcp_v6(self):
        pkt = scapy.Ether(dst="33:33:00:01:00:02")/scapy.IPv6(dst="ff02::1:2")/scapy.UDP(sport=546, dport=547)/scapy.DHCP6_Solicit()
        self._enviar(pkt, "DHCPv6 Solicit")

    def gerar_quic(self):
        pkt = scapy.Ether()/scapy.IPv6(dst="ff02::1")/scapy.UDP(sport=41795, dport=443)/scapy.Raw(load="Dados QUIC v6")
        self._enviar(pkt, "QUIC/HTTPS (IPv6)")

    def gerar_wifi_beacon(self):
        dot11 = scapy.Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")
        beacon = scapy.Dot11Beacon(cap="ESS+privacy")
        essid = scapy.Dot11Elt(ID="SSID", info="Rede_Teste_RC", len=len("Rede_Teste_RC"))
        pkt = scapy.RadioTap()/dot11/beacon/essid
        self._enviar(pkt, "802.11 Beacon")

    def gerar_wifi_probe(self):
        dot11 = scapy.Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2="66:77:88:99:AA:BB", addr3="ff:ff:ff:ff:ff:ff")
        probe = scapy.Dot11ProbeReq()
        essid = scapy.Dot11Elt(ID="SSID", info="Procurando_Rede", len=len("Procurando_Rede"))
        rates = scapy.Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        pkt = scapy.RadioTap()/dot11/probe/essid/rates
        self._enviar(pkt, "802.11 Probe Request")

    def gerar_tudo(self):
        """Executa uma bateria completa de testes"""
        metodos = [
            self.gerar_icmp_v4, self.gerar_icmp_v6, self.gerar_ip_fragmentado,
            self.gerar_dns, self.gerar_http, self.gerar_telnet, 
            self.gerar_dhcp_v4, self.gerar_dhcp_v6, self.gerar_quic, 
            self.gerar_wifi_beacon, self.gerar_wifi_probe
        ]
        for metodo in metodos:
            metodo()

def menu():
    interface = "wlp3s0" 
    gerador = GeradorPacotes(interface)

    opcoes = {
        "1": ("ICMPv4 (Ping)", gerador.gerar_icmp_v4),
        "2": ("ICMPv6 (Ping)", gerador.gerar_icmp_v6),
        "3": ("IP Fragmentado (IPv4)", gerador.gerar_ip_fragmentado),
        "4": ("DNS Query", gerador.gerar_dns),
        "5": ("HTTP GET (TCP)", gerador.gerar_http),
        "6": ("Telnet Login (TCP 23)", gerador.gerar_telnet),
        "7": ("DHCPv4 Discover", gerador.gerar_dhcp_v4),
        "8": ("DHCPv6 Solicit", gerador.gerar_dhcp_v6),
        "9": ("QUIC/HTTPS (UDP 443)", gerador.gerar_quic),
        "10": ("802.11 Beacon (Wi-Fi)", gerador.gerar_wifi_beacon),
        "11": ("802.11 Probe Request", gerador.gerar_wifi_probe),
        "12": ("ENVIAR BATERIA COMPLETA", gerador.gerar_tudo),
        "0": ("Sair", sys.exit)
    }

    while True:
        print("\n" + "="*40)
        print(f" GERADOR DE TRÁFEGO PARA SNIFFER ({interface})")
        print("="*40)
        for k in sorted(opcoes.keys(), key=lambda x: int(x)):
            print(f"[{k}] {opcoes[k][0]}")
        
        escolha = input("\n➤ Selecione o pacote a injetar: ")
        
        if escolha in opcoes:
            try:
                opcoes[escolha][1]()
                print("[!] Pacote injetado com sucesso.")
            except PermissionError:
                print("[E] ERRO: Permissão negada. Use 'sudo python3 gerador.py'")
                break
            except Exception as e:
                print(f"[E] ERRO inesperado: {e}")
        else:
            print("[!] Opção inválida.")

if __name__ == "__main__":
    menu()
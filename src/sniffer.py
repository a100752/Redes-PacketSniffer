import scapy.all as scapy

# Desativar modo promíscuo — no macOS, o modo promíscuo interfere com o driver Wi-Fi
# e causa perda de conectividade. Sem promíscuo, o sniffer captura apenas tráfego
# destinado a/originado pelo próprio host, o que é suficiente para os testes.
scapy.conf.sniff_promisc = 0

class PacketSniffer:
    def __init__(self, interface): # Construtor da classe que inicia(configura) o PacketSniffer com a interface dada
        self.interface = interface

    def start_capture(self, callback_func, bpf_filter="", count=10): # Inicia a captura com a interface dada
        packets = scapy.sniff( # função de captura da lib scapy do python
            iface=self.interface, 
            filter=bpf_filter, 
            store=True, 
            count=count,
            prn=callback_func
        )
        return packets # Retorna uma lista de pacotes
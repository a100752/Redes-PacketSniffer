import scapy.all as scapy
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console() # lib rich do python para melhor interface

def get_config(): 
    # Pede os dados de configuração para captura
    rprint(Panel("[bold white]Sniffer Setup[/bold white]", border_style="magenta", expand=False)) # è criado um painel para o cabeçalho do setup(lib rich)
    
    iface = input("➤ Interface (e.g., eth0, wlp3s0): ") # Pede a interface
    if (iface not in scapy.get_if_list()): iface = ""
    
    limit_input = input("➤ Packet limit (<= 0 or nothing for infinite captures): ") # Pede o número de pacotes a capturar
    limit = int(limit_input) if limit_input.strip() else 0
    
    bpf = input("➤ BPF Filter (e.g., icmp, tcp port 80): ") # Filtro de pacotes tipo o Wireshark
    
    return iface, limit, bpf

def show_interfaces(): 
    # Mostra as interfaces disponíveis numa tabela organizada.
    interfaces = scapy.get_if_list() 
    
    # Criar uma tabela estilizada(Coisas da lib rich)
    table = Table(
        title="[bold cyan]Available Network Interfaces[/bold cyan]", 
        header_style="bold white",
        border_style="cyan"
    )
    
    table.add_column("ID", justify="center", style="yellow")
    table.add_column("Interface Name", style="blue")

    for i, iface in enumerate(interfaces):
        table.add_row(str(i + 1), iface)

    # Imprime a tabela no ecrã
    console.print(table)
import sys
import os
from sniffer import PacketSniffer
import interface as interface
import protocol as protocol
from datetime import datetime
import scapy.all as scapy
import time

# Importação da biblioteca Rich para a interface visual
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

console = Console() # lib rich do python para melhor interface

# Variável para numerar os pacotes no live_print
pkt_count = 0

# Variável de permissão de escrita nos log.txt(default é 0)
logs = 0

# Dicionário(map) para contar as capturas de diferentes protocolos
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "IPv6" : 0, "Other": 0}
statsSize = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "IPv6" : 0, "Other": 0}

def main():
    global pkt_count
    global logs, stats
    # Verifica se é root
    if os.getuid() != 0:
        rprint("[bold red]Please run as root (sudo).[/bold red]")
        sys.exit(1)

    session_count = 0 # Contador de sessões de captura
    os.system('clear')
    
    # Welcome
    rprint(Panel("[bold white]Welcome to the Packet Sniffer![/bold white]", expand=False))

   # with open("log.txt", "a", encoding="utf-8") as ficheiro: # A cada run do programa é feito esta escrita nos logs para melhor aparência
    #            ficheiro.write("\n" + "="*15 + "New Session" +  "="*15 +  "\n")

    while True:

        log_status = "[green]Allowed[/green]" if logs == 1 else "[red]Not Allowed[/red]" # Muda de acordo a permissão de guardar os dados no log.txt
        # Menu principal visual
        menu_content = (
            "[cyan][1][/cyan] Configure and Start Sniffer\n"
            "[cyan][2][/cyan] List of Available Interfaces\n"
            "[cyan][3][/cyan] Show Capture logs\n"
            "[cyan][4][/cyan] Clean Capture logs\n"
            "[cyan][5][/cyan] Clean Screen\n"
            f"[cyan][6][/cyan] Allow saving on the log.txt ({log_status})\n"
            "[red][7][/red] Exit"
        )
        rprint(Panel(menu_content, title="[bold white]Menu[/bold white]", border_style="blue", expand=False))
        
        choice = input("Select an option: ")

        if choice == '7':
            rprint("[bold red]Exiting...[/bold red]") # Fecha o programa
            sys.exit(0)

        elif choice == '6': # permite trocar o valor da variável global 'logs' para que permita ou não guardar no ficheiro log.txt
            if (logs == 0):
                rprint("[bold green]Saving allowed")
                logs = 1
            else:
                rprint("[bold red]Saving not allowed")
                logs = 0
        
        elif choice == '5':
            os.system('clear') # Aplica o comando clear do linux para melhor visão
            continue
        
        elif choice == '4':
            if not os.system('rm log.txt 2>/dev/null'): # Remove(Limpa) o ficheiro de logs
                rprint("[bold green]File Cleaned[/bold green]")
                count = 0
            else:
                rprint("[yellow]Log file already empty or not found.[/yellow]")
            continue
        
        elif choice == '3':
            rprint("[bold magenta]--- Capture Logs ---[/bold magenta]")
            if os.system('cat log.txt'): # Abre o ficheiro de logs das capturas
                rprint("[bold red]No packets sniffed yet[/bold red]")
            continue
        
        elif choice == '2':
            interface.show_interfaces() # Aplica a função de mostrar as interfaces disponíveis
            input("\nPress Enter to return to menu...")
            continue 

        elif choice == '1':
            iface, limit, bpf = interface.get_config() # Vai pedir os dados de configuração da captura

            if logs == 1: # escreve no log.txt a data e hora do inicio da captura
                with open("log.txt", "a", encoding="utf-8") as ficheiro:
                    if session_count == 0:
                        ficheiro.write("\n" + "="*20 + " SNIFFER NEW SESSION START " + "="*20 + "\n")
                    dt_object_now = datetime.now()
                    format_date_now = dt_object_now.strftime("%d/%m/%Y %H:%M:%S")
                    ficheiro.write("\n" + "-"*30 + f"{format_date_now}" +  "\n")
            
            sniffer = PacketSniffer(iface) # Inicia o PacketSniffer
            msg_limit = "indefinite" if limit <= 0 else f"{limit}" # Para escrever no ecrã se é infinito
            interf = 'Standard System Interface' if iface == '' else f"{iface}" # Se foi deixado em branco(captura na interface pré-definida do sistema)
            rprint(f"\n[bold green][*][/bold green] Sniffing [bold cyan]{msg_limit}[/bold cyan] packages on [bold white]{interf}[/bold white]...")
            rprint("[dim](Press Ctrl+C to stop capture)[/dim]\n")

            # Reset dos contadores de diferentes protocolos
            for key in stats: stats[key] = 0
            for key in statsSize: statsSize[key] = 0

            # Reset do contador para esta captura específica
            pkt_count = 0

            def live_print(pkt): # função que permite a captura um a um dos pacotes
                global pkt_count, stats
                pkt_count += 1
                dt = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S")
                
                # --- Contador de protocolos e seu tamanho  --- 
                if pkt.haslayer(scapy.TCP): 
                    stats["TCP"] += 1
                    statsSize["TCP"] += len(pkt)
                elif pkt.haslayer(scapy.UDP): 
                    stats["UDP"] += 1
                    statsSize["UDP"] += len(pkt)
                elif pkt.haslayer(scapy.ICMP) or pkt.haslayer(scapy.ICMPv6EchoRequest): 
                    stats["ICMP"] += 1
                    statsSize["ICMP"] += len(pkt)
                elif pkt.haslayer(scapy.ARP): 
                    stats["ARP"] += 1
                    statsSize["ARP"] += len(pkt)
                elif pkt.haslayer(scapy.IPv6): 
                    stats["IPv6"] += 1
                    statsSize["IPv6"] += len(pkt)
                else: 
                    stats["Other"] += 1
                    statsSize["Other"] += len(pkt)

                # Interface de detalhes durante a captura
                p_detail = protocol.get_detailed_info(pkt) 
                rprint(Panel(
                    f"[bold white]{p_detail}[/bold white]", 
                    title=f"[bold cyan]Packet #{pkt_count}[/bold cyan] - [dim]{dt}[/dim]",
                    border_style="green",
                    expand=False
                ))
                time.sleep(0.5) # Pausa entre escrituras de pacotes no ecrã
            
            try:
                # O Scapy com count<=0 corre até ser interrompido
                pkts = sniffer.start_capture(live_print, bpf, limit) # Começa a capturar
            except KeyboardInterrupt: 
                # Captura o sinal de interrupção (Ctrl+C)
                rprint("\n[yellow][!] Capture stopped by user.[/yellow]")

            # --- Tabela das Estatísticas dos protocolos ---
            if len(pkts) > 0:
                table = Table(title="Capture Statistics", border_style="cyan")
                table.add_column("Protocol", style="magenta")
                table.add_column("Count", justify="right", style="green")
                table.add_column("Percentage(By Qtd)", justify="right", style="yellow")
                table.add_column("Total Size", justify="right", style="yellow")
                table.add_column("Percentage(By Size)", justify="right", style="yellow")

                # calcula o total apenas do que está nos dicionários
                total_pkts_visible = sum(stats.values())
                total_size_visible = sum(statsSize.values())

                for proto in stats.keys():
                    count = stats[proto]
                    size = statsSize.get(proto, 0)
                    
                    if count > 0:
                        # Calcula as percentagens tendo em conta a quantidade e tamanho dos pacotes capturados
                        pct_count = (count / total_pkts_visible) * 100
                        pct_size = (size / total_size_visible) * 100 if total_size_visible > 0 else 0
                        
                        table.add_row(
                            proto, 
                            str(count), 
                            f"{pct_count:.1f}%", 
                            f"{size} bytes", 
                            f"{pct_size:.1f}%"
                        )
                console.print(table)

            # Grava no log
            if logs == 1:
                session_count += 1
                with open("log.txt", "a", encoding="utf-8") as ficheiro:
                    ficheiro.write(f"\n\033[1m--- Capture {session_count} ---\033[0m\n")
                    for i, p in enumerate(pkts):
                        dt_obj = datetime.fromtimestamp(float(p.time))
                        fmt_date = dt_obj.strftime("%d/%m/%Y %H:%M:%S")
                        ficheiro.write(f"[{i + 1}] [{fmt_date}]\n{p.summary()}\n\n")
                        ficheiro.write("\033[1mDETAILED PACKET INFO\033[0m\n")
                        ficheiro.write(f"\n{protocol.get_detailed_info(p)}\n")
                        ficheiro.write("-------------------------------------------------------\n")

            if logs == 1: # se foi permito guardar ou não
                rprint(f"\n[bold green][*] Finished. Total: {len(pkts)} packets recorded in log.txt.[/bold green]")
            else:
                rprint(f"\n[bold green][*] Finished. Total: {len(pkts)}[/bold green]")
            
            input("\nPress Enter to return to menu...")
            os.system('clear') # só para limpeza e beleza do sniffer
            continue 
        else:
            rprint("\n[bold red][!] Invalid Option[/bold red]\n")
            continue

if __name__ == "__main__": # Inicia a main(Necessário em Python)
    main()
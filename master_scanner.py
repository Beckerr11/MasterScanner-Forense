import deep_memory_scanner
import memory_dumper
import kernel_rootkit_detector
import sys
import os
import json
import time

def run_master_scan():
    print("="*60)
    print("   MASTER MEMORY SCANNER - SECURITY CONSULTANT TOOL")
    print("="*60)
    print(f"[*] Inicio da varredura: {time.ctime()}")

    all_findings = []

    # 1. Varredura de Processos e Memoria Viva (User-Mode)
    print("\n[1] Fase de Varredura de Processos (User-Mode)...")
    deep_memory_scanner.main()
    if os.path.exists("memory_scan_results.json"):
        with open("memory_scan_results.json", "r") as f:
            user_mode_findings = json.load(f)
        all_findings.extend(user_mode_findings)

    # 2. Varredura de Kernel-Mode e Deteccao de Rootkits
    if sys.platform == "win32":
        print("\n[2] Fase de Varredura de Kernel-Mode e Deteccao de Rootkits...")
        
        # Verificacao de drivers
        drivers = memory_dumper.check_kernel_drivers()
        print(f"[+] Total de drivers carregados: {len(drivers)}")
        with open("kernel_drivers.json", "w") as f:
            json.dump(drivers, f, indent=4)
        print("[*] Lista de drivers salva em kernel_drivers.json")

        # Deteccao de Rootkits
        rootkit_findings = kernel_rootkit_detector.analyze_kernel_for_rootkits()
        if rootkit_findings:
            all_findings.extend(rootkit_findings)
            with open("kernel_rootkit_findings.json", "w") as f:
                json.dump(rootkit_findings, f, indent=4)
            print("[*] Deteccoes de rootkit salvas em kernel_rootkit_findings.json")
        else:
            print("[-] Nenhuma deteccao de rootkit de kernel encontrada (via user-mode). ")

        # 3. Fase de Extracao (Subtracao) de Informacoes Suspeitas
        if os.path.exists("memory_scan_results.json"):
            print("\n[3] Fase de Extracao (Subtracao) de Memoria Suspeita...")
            
            if not os.path.exists("dumps"):
                os.makedirs("dumps")

            for entry in user_mode_findings:
                pid = entry["process"]["pid"]
                name = entry["process"]["name"]
                for detection in entry["detections"]:
                    if detection["type"] == "RWX_Private_Memory":
                        base_addr = int(detection["address"], 16)
                        size = detection["size"]
                        # CORRECAO DA SINTAXE ABAIXO:
                        addr_str = detection["address"]
                        output_file = f"dumps/pid_{pid}_{name}_{addr_str}.bin"
                        print(f"[*] Realizando dump de {name} (PID: {pid}) no endereco {addr_str}...")
                        memory_dumper.dump_memory_region(pid, base_addr, size, output_file)
    else:
        print("\n[!] Ambiente nao-Windows detectado. Algumas fases de kernel e extracao foram ignoradas.")

    if all_findings:
        print("\n[+] RESUMO GERAL DAS DETECCOES:")
        print(json.dumps(all_findings, indent=4))
        with open("master_scan_summary.json", "w") as f:
            json.dump(all_findings, f, indent=4)
        print("[*] Resumo geral salvo em master_scan_summary.json")
    else:
        print("\n[-] Nenhuma deteccao geral encontrada.")

    print("\n" + "="*60)
    print(f"[*] Varredura concluida em: {time.ctime()}")
    print("="*60)

if __name__ == "__main__":
    run_master_scan()

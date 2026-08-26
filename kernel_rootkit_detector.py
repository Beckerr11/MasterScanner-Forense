import ctypes
import sys
import json

# --- Constantes e Estruturas para Windows API (ctypes) ---
if sys.platform == "win32":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    EnumDeviceDrivers = psapi.EnumDeviceDrivers
    EnumDeviceDrivers.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    EnumDeviceDrivers.restype = ctypes.c_bool

    GetDeviceDriverBaseNameW = psapi.GetDeviceDriverBaseNameW
    GetDeviceDriverBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
    GetDeviceDriverBaseNameW.restype = ctypes.c_ulong

    GetDeviceDriverFileNameW = psapi.GetDeviceDriverFileNameW
    GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
    GetDeviceDriverFileNameW.restype = ctypes.c_ulong


def check_unsigned_drivers():
    """Enumera drivers carregados usando uma heurística de caminho em user-mode.

    A função não afirma verificar assinatura digital criptograficamente. Drivers fora dos
    caminhos padrão do Windows são retornados como itens para revisão manual.
    """
    if sys.platform != "win32":
        return []

    findings = []
    try:
        drivers_base_addresses = (ctypes.c_void_p * 1024)()
        cb = ctypes.sizeof(drivers_base_addresses)
        needed = ctypes.c_ulong()

        if EnumDeviceDrivers(ctypes.byref(drivers_base_addresses), cb, ctypes.byref(needed)):
            count = int(needed.value / ctypes.sizeof(ctypes.c_void_p))
            for i in range(count):
                driver_base = drivers_base_addresses[i]
                if not driver_base:
                    continue

                name_buffer = ctypes.create_unicode_buffer(1024)
                GetDeviceDriverBaseNameW(driver_base, name_buffer, ctypes.sizeof(name_buffer))
                driver_name = name_buffer.value

                path_buffer = ctypes.create_unicode_buffer(1024)
                GetDeviceDriverFileNameW(driver_base, path_buffer, ctypes.sizeof(path_buffer))
                driver_path = path_buffer.value

                normalized_path = driver_path.lower() if driver_path else ""
                is_system_path = (
                    "\\windows\\system32\\drivers\\" in normalized_path
                    or "\\windows\\system32\\" in normalized_path
                )

                if not is_system_path:
                    findings.append(
                        {
                            "type": "Third-Party Driver Review",
                            "name": driver_name,
                            "path": driver_path,
                            "base_address": hex(driver_base or 0),
                            "details": (
                                "Driver fora dos caminhos padrão do sistema. "
                                "A heurística não comprova ausência de assinatura nem comportamento malicioso."
                            ),
                        }
                    )
    except Exception as exc:
        print(f"[!] Erro ao enumerar drivers para revisão: {exc}")

    return findings


def check_ssdt_integrity():
    """Retorna somente evidência observável de SSDT hooking.

    A implementação atual é user-mode e não possui acesso confiável à SSDT. Portanto,
    ausência de uma verificação implementada não pode ser transformada em finding.
    """
    return []


def check_hidden_processes():
    """Retorna somente evidência observável de processos ocultos/DKOM.

    Uma comparação confiável exige uma fonte independente em kernel-mode. Enquanto essa
    capacidade não existir, o scanner não cria findings simulados.
    """
    return []


def analyze_kernel_for_rootkits():
    """Orquestra apenas verificações que produzem evidência observável."""
    print("[*] Iniciando análise de Kernel para Rootkits...")
    kernel_findings = []

    print("[*] Verificando drivers de terceiros para revisão...")
    driver_findings = check_unsigned_drivers()
    if driver_findings:
        kernel_findings.extend(driver_findings)

    print("[*] SSDT: verificação kernel-mode não implementada; nenhum finding simulado será criado.")
    ssdt_findings = check_ssdt_integrity()
    if ssdt_findings:
        kernel_findings.extend(ssdt_findings)

    print("[*] DKOM: verificação kernel-mode não implementada; nenhum finding simulado será criado.")
    hidden_process_findings = check_hidden_processes()
    if hidden_process_findings:
        kernel_findings.extend(hidden_process_findings)

    return kernel_findings


if __name__ == "__main__":
    if sys.platform == "win32":
        results = analyze_kernel_for_rootkits()
        if results:
            print("\n[+] ITENS DE REVISÃO ENCONTRADOS:")
            print(json.dumps(results, indent=4, ensure_ascii=False))
        else:
            print("\n[-] Nenhuma evidência observável encontrada pelas verificações implementadas.")
    else:
        print("[*] Este módulo é projetado para Windows.")

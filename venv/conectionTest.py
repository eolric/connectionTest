import os
import platform
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from scapy.all import ARP, Ether, srp
from scapy.config import conf
import speedtest

conf.use_pcap = True  # Para Windows con Npcap

# Configura tu red local
RED_LOCAL = "192.168.40.0/24"

# =========================
# ESCANEO DE RED
# =========================
def escanear_red_arp(red):
    """Escanea la red usando ARP (requiere Npcap o root)."""
    print(f"🔍 Escaneando red local con ARP: {red}")
    try:
        paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=red)
        result = srp(paquete, timeout=2, verbose=0)[0]
        dispositivos = []
        for _, recibido in result:
            dispositivos.append({'IP': recibido.psrc, 'MAC': recibido.hwsrc})
        return dispositivos
    except Exception as e:
        print(f"⚠️ Error en escaneo ARP: {e}")
        return []

def escanear_red_ping(rango):
    """Escanea usando ping sweep (más lento pero sin privilegios especiales)."""
    print(f"🔍 Escaneando red local con ping sweep: {rango}.x")
    dispositivos = []
    for i in range(1, 255):
        ip = f"{rango}.{i}"
        respuesta = subprocess.run(["ping", "-n", "1", "-w", "300", ip], capture_output=True)
        if "TTL=" in respuesta.stdout.decode("utf-8"):
            dispositivos.append({'IP': ip, 'MAC': 'N/A'})
    return dispositivos

# =========================
# MEDICIÓN DE LATENCIA
# =========================
def medir_ping(ip):
    """Mide el tiempo promedio de ping a una IP (en ms)."""
    sistema = platform.system().lower()
    if sistema == "windows":
        comando = ["ping", "-n", "1", "-w", "300", ip]
    else:
        comando = ["ping", "-c", "1", "-W", "1", ip]

    try:
        salida = subprocess.check_output(comando).decode("latin-1", errors="ignore")
        if "TTL=" in salida:
            # Busca tiempo en ms
            if "tiempo=" in salida:
                tiempo = salida.split("tiempo=")[1].split("ms")[0].strip()
                return float(tiempo)
            elif "time=" in salida:
                tiempo = salida.split("time=")[1].split("ms")[0].strip()
                return float(tiempo)
        return None
    except subprocess.CalledProcessError:
        return None

# =========================
# TEST DE VELOCIDAD
# =========================
def medir_velocidad():
    print("⚡ Ejecutando test de velocidad (Speedtest.net)...")
    s = speedtest.Speedtest()
    s.get_best_server()
    descarga = s.download() / 1e6
    subida = s.upload() / 1e6
    ping = s.results.ping
    return descarga, subida, ping

# =========================
# PROGRAMA PRINCIPAL
# =========================
def main():
    print("\n🧭 Iniciando diagnóstico de red...\n")

    # Intentar escanear con ARP, si falla, usar ping sweep
    dispositivos = escanear_red_arp(RED_LOCAL)
    if not dispositivos:
        dispositivos = escanear_red_ping("192.168.40")

    # Agregar servidores externos
    externos = [
        {"IP": "8.8.8.8", "MAC": "Servidor externo"},
        {"IP": "1.1.1.1", "MAC": "Servidor externo"},
        {"IP": "google.com", "MAC": "Servidor externo"},
    ]
    dispositivos.extend(externos)

    # Medir latencia
    for disp in dispositivos:
        disp["Latencia (ms)"] = medir_ping(disp["IP"])

    # Crear tabla
    df = pd.DataFrame(dispositivos)
    print("\n📊 Resultados del diagnóstico:\n")
    print(df.to_string(index=False))

    # Guardar CSV con timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    df.to_csv(f"diagnostico_red_{timestamp}.csv", index=False)

    # Gráfico de latencia
    df_ping = df.dropna(subset=["Latencia (ms)"])
    if not df_ping.empty:
        plt.figure(figsize=(10, 5))
        plt.bar(df_ping["IP"], df_ping["Latencia (ms)"])
        plt.xticks(rotation=45, ha='right')
        plt.ylabel("Latencia (ms)")
        plt.title("Latencia de Dispositivos en la Red")
        plt.tight_layout()
        plt.savefig(f"latencia_red_{timestamp}.png")
        plt.show()

    # Test de velocidad
    descarga, subida, ping = medir_velocidad()
    print("\n⚙️  Resultados de velocidad:\n")
    print(f" Velocidad Descarga (Mbps): {descarga:.2f}")
    print(f" Velocidad Subida (Mbps): {subida:.2f}")
    print(f" Ping Servidor Speedtest (ms): {ping:.1f}")

if __name__ == "__main__":
    main()

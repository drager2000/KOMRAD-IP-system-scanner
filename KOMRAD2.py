import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import re
import sys
import subprocess
import os
from packaging import version

# Función para instalar dependencias automáticamente
def install_dependencies():
    required_packages = {
        'scapy': 'scapy',
        'python-nmap': 'python-nmap',
        'packaging': 'packaging'
    }
    
    installed_packages = []
    missing_packages = []
    
    # Verificar qué paquetes están instalados
    for package_name, pip_name in required_packages.items():
        try:
            if package_name == 'python-nmap':
                __import__('nmap')
            else:
                __import__(package_name)
            installed_packages.append(package_name)
        except ImportError:
            missing_packages.append((package_name, pip_name))
    
    # Instalar paquetes faltantes
    if missing_packages:
        print("Instalando dependencias faltantes...")
        for package_name, pip_name in missing_packages:
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', pip_name])
                print(f"✓ {package_name} instalado correctamente")
            except subprocess.CalledProcessError:
                print(f"✗ Error instalando {package_name}")
                return False
        print("Todas las dependencias se instalaron correctamente")
    else:
        print("Todas las dependencias están instaladas")
    
    return True

# Instalar dependencias al inicio
if not install_dependencies():
    messagebox.showerror("Error", "No se pudieron instalar las dependencias necesarias")
    sys.exit(1)

# Ahora importamos las dependencias después de la instalación
try:
    from scapy.all import ARP, Ether, srp
    import nmap
    from packaging import version
except ImportError as e:
    messagebox.showerror("Error", f"Error importando dependencias: {e}")
    sys.exit(1)

class AndroidDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(" KOMRAD ")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variables
        self.target_ip = tk.StringVar()
        self.scanning = False
        self.dependencies_installed = False
        self.subnet_var = tk.StringVar(value="auto")  # auto o manual
        
        self.setup_ui()
        self.check_dependencies()
        
    def check_dependencies(self):
        """Verifica si todas las dependencias están instaladas"""
        try:
            # Verificar imports
            from scapy.all import ARP, Ether, srp
            import nmap
            
            self.dependencies_installed = True
            self.update_status("Dependencias instaladas - Listo para escanear")
        except ImportError as e:
            self.update_status(f"Error en dependencias: {e}")
            self.install_dependencies_gui()
            
    def install_dependencies_gui(self):
        """Interfaz para instalar dependencias"""
        install_window = tk.Toplevel(self.root)
        install_window.title("Instalación de Dependencias")
        install_window.geometry("400x200")
        install_window.transient(self.root)
        install_window.grab_set()
        
        ttk.Label(install_window, text="Se necesitan instalar dependencias", 
                 font=("Arial", 12, "bold")).pack(pady=20)
        
        ttk.Label(install_window, text="El programa instalará automáticamente:\n- scapy\n- python-nmap\n- packaging").pack(pady=10)
        
        progress = ttk.Progressbar(install_window, mode='indeterminate')
        progress.pack(pady=10, fill=tk.X, padx=20)
        
        status_label = ttk.Label(install_window, text="Haz clic en Instalar para continuar")
        status_label.pack(pady=5)
        
        def do_install():
            install_btn.config(state=tk.DISABLED)
            progress.start()
            status_label.config(text="Instalando...")
            
            def install_thread():
                success = install_dependencies()
                install_window.after(0, lambda: finish_install(success))
            
            threading.Thread(target=install_thread, daemon=True).start()
        
        def finish_install(success):
            progress.stop()
            if success:
                status_label.config(text="✓ Instalación completada")
                self.dependencies_installed = True
                install_window.after(2000, install_window.destroy)
                self.update_status("Dependencias instaladas - Listo para escanear")
            else:
                status_label.config(text="✗ Error en la instalación")
                install_btn.config(state=tk.NORMAL)
        
        install_btn = ttk.Button(install_window, text="Instalar Dependencias", 
                               command=do_install)
        install_btn.pack(pady=10)
        
    def setup_ui(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Título
        title_label = ttk.Label(main_frame, text=" KOMRAD ", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Frame de configuración de subred
        subnet_frame = ttk.LabelFrame(main_frame, text="Configuración de Subred", padding="10")
        subnet_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        subnet_frame.columnconfigure(1, weight=1)
        
        # Opción de detección automática
        ttk.Radiobutton(subnet_frame, text="Detección automática de subredes", 
                       variable=self.subnet_var, value="auto").grid(row=0, column=0, sticky=tk.W, pady=2)
        
        # Opción manual
        manual_frame = ttk.Frame(subnet_frame)
        manual_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        manual_frame.columnconfigure(1, weight=1)
        
        ttk.Radiobutton(manual_frame, text="Subred manual:", 
                       variable=self.subnet_var, value="manual").grid(row=0, column=0, sticky=tk.W)
        
        self.manual_subnet_entry = ttk.Entry(manual_frame, textvariable=self.target_ip, width=20, font=("Arial", 10))
        self.manual_subnet_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 10))
        
        ttk.Label(manual_frame, text="Ejemplo: 192.168.1.0/24").grid(row=0, column=2, sticky=tk.W)
        
        # Frame de entrada para IP individual
        input_frame = ttk.Frame(main_frame)
        input_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        input_frame.columnconfigure(1, weight=1)
        
        ttk.Label(input_frame, text="IP individual:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ip_entry = ttk.Entry(input_frame, width=20, font=("Arial", 10))
        ip_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 10))
        
        # Botones
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=0, column=2, sticky=tk.W)
        
        single_scan_btn = ttk.Button(button_frame, text="Escanear IP", 
                                   command=self.scan_single_ip, width=12)
        single_scan_btn.grid(row=0, column=0, padx=(0, 5))
        
        network_scan_btn = ttk.Button(button_frame, text="Escanear Subred", 
                                    command=self.scan_subnet, width=12)
        network_scan_btn.grid(row=0, column=1, padx=(0, 5))
        
        multi_subnet_btn = ttk.Button(button_frame, text="Escanear Múltiples Subredes", 
                                    command=self.scan_all_subnets, width=20)
        multi_subnet_btn.grid(row=0, column=2, padx=(0, 5))
        
        clear_btn = ttk.Button(button_frame, text="Limpiar", 
                             command=self.clear_results, width=10)
        clear_btn.grid(row=0, column=3)
        
        # Frame para resultados
        results_frame = ttk.LabelFrame(main_frame, text="📊 Resultados del Escaneo", padding="10")
        results_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(20, 0))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Treeview para mostrar resultados
        columns = ("IP", "MAC", "Fabricante", "Modelo", "Sistema Operativo", "Subred", "Estado")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        # Configurar columnas
        column_widths = {"IP": 120, "MAC": 120, "Fabricante": 120, "Modelo": 120, 
                        "Sistema Operativo": 120, "Subred": 100, "Estado": 80}
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbar para treeview
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Barra de progreso
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Label de estado
        self.status_label = ttk.Label(main_frame, text="Verificando dependencias...")
        self.status_label.grid(row=5, column=0, columnspan=3, pady=(5, 0))
        
        # Información adicional
        info_label = ttk.Label(main_frame, 
                              text="💡 'Escanear Múltiples Subredes' probará las subredes más comunes automáticamente",
                              font=("Arial", 8), foreground="gray")
        info_label.grid(row=6, column=0, columnspan=3, pady=(10, 0))
        
    def scan_single_ip(self):
        if not self.dependencies_installed:
            messagebox.showerror("Error", "Las dependencias no están instaladas correctamente")
            return
            
        ip = self.target_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "Por favor ingresa una dirección IP")
            return
            
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Dirección IP inválida")
            return
            
        threading.Thread(target=self._scan_single_ip, args=(ip,), daemon=True).start()
        
    def scan_subnet(self):
        if not self.dependencies_installed:
            messagebox.showerror("Error", "Las dependencias no están instaladas correctamente")
            return
            
        if self.subnet_var.get() == "auto":
            network = self.get_local_network()
            if not network:
                messagebox.showerror("Error", "No se pudo detectar la red local")
                return
        else:
            network = self.target_ip.get().strip()
            if not network:
                messagebox.showerror("Error", "Por favor ingresa una subred")
                return
            if not self.validate_subnet(network):
                messagebox.showerror("Error", "Formato de subred inválido. Use formato CIDR: 192.168.1.0/24")
                return
                
        threading.Thread(target=self._scan_subnet, args=(network,), daemon=True).start()
        
    def scan_all_subnets(self):
        if not self.dependencies_installed:
            messagebox.showerror("Error", "Las dependencias no están instaladas correctamente")
            return
            
        threading.Thread(target=self._scan_all_subnets, daemon=True).start()
        
    def _scan_single_ip(self, ip):
        self.set_scanning(True)
        self.clear_results()
        
        try:
            self.update_status(f"Verificando conectividad de {ip}...")
            
            if self.ping_host(ip):
                self.update_status(f"Escaneando dispositivo {ip}...")
                
                # Obtener información del dispositivo
                device_info = self.get_device_info(ip)
                
                # Determinar subred
                subnet = self.get_subnet_from_ip(ip)
                
                # Determinar estado
                status = "✅ Activo" if device_info else "⚠️ Sin info"
                
                # Agregar a la lista de resultados
                self.add_result(ip, 
                              device_info.get('mac', 'Desconocida'),
                              device_info.get('vendor', 'Desconocido'),
                              device_info.get('model', 'Desconocido'),
                              device_info.get('os', 'Desconocido'),
                              subnet,
                              status)
                
                self.update_status(f"Escaneo completado para {ip}")
            else:
                subnet = self.get_subnet_from_ip(ip)
                self.add_result(ip, "N/A", "N/A", "N/A", "N/A", subnet, "❌ Inactivo")
                self.update_status(f"Host {ip} no responde")
                
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            subnet = self.get_subnet_from_ip(ip) if self.validate_ip(ip) else "Desconocida"
            self.add_result(ip, "Error", "Error", "Error", f"Error: {str(e)}", subnet, "❌ Error")
        finally:
            self.set_scanning(False)
            
    def _scan_subnet(self, network):
        self.set_scanning(True)
        self.clear_results()
        
        try:
            self.update_status(f"Escaneando subred {network}...")
            
            # Escanear dispositivos en la subred usando ARP
            devices = self.scan_arp(network)
            
            if not devices:
                self.update_status(f"No se encontraron dispositivos en la subred {network}")
                return
                
            self.update_status(f"Encontrados {len(devices)} dispositivos en {network}. Analizando...")
            
            for i, (ip, mac) in enumerate(devices):
                self.update_status(f"Analizando dispositivo {i+1}/{len(devices)}: {ip}")
                
                device_info = self.get_device_info(ip)
                status = "✅ Activo"
                
                # Verificar si es un dispositivo Android
                if self.is_android_device(device_info):
                    status = "🤖 Android"
                
                self.add_result(ip, mac, 
                              device_info.get('vendor', 'Desconocido'),
                              device_info.get('model', 'Desconocido'),
                              device_info.get('os', 'Desconocido'),
                              network,
                              status)
            
            self.update_status(f"Escaneo de {network} completado. Procesados {len(devices)} dispositivos")
            
        except Exception as e:
            self.update_status(f"Error en escaneo de subred: {str(e)}")
        finally:
            self.set_scanning(False)
            
    def _scan_all_subnets(self):
        self.set_scanning(True)
        self.clear_results()
        
        try:
            self.update_status("Detectando subredes disponibles...")
            
            # Obtener todas las subredes (sin netifaces)
            subnets = self.get_all_subnets()
            
            if not subnets:
                self.update_status("No se pudieron detectar subredes")
                return
                
            self.update_status(f"Encontradas {len(subnets)} subredes. Escaneando...")
            
            total_devices = 0
            for i, subnet in enumerate(subnets):
                self.update_status(f"Escaneando subred {i+1}/{len(subnets)}: {subnet}")
                
                devices = self.scan_arp(subnet)
                if devices:
                    self.update_status(f"Encontrados {len(devices)} dispositivos en {subnet}")
                    
                    for ip, mac in devices:
                        device_info = self.get_device_info(ip)
                        status = "✅ Activo"
                        
                        if self.is_android_device(device_info):
                            status = "🤖 Android"
                            
                        self.add_result(ip, mac,
                                      device_info.get('vendor', 'Desconocido'),
                                      device_info.get('model', 'Desconocido'),
                                      device_info.get('os', 'Desconocido'),
                                      subnet,
                                      status)
                    
                    total_devices += len(devices)
                else:
                    self.update_status(f"No se encontraron dispositivos en {subnet}")
            
            self.update_status(f"Escaneo completado. {total_devices} dispositivos encontrados en {len(subnets)} subredes")
            
        except Exception as e:
            self.update_status(f"Error en escaneo múltiple: {str(e)}")
        finally:
            self.set_scanning(False)
            
    def get_all_subnets(self):
        """Obtiene todas las subredes disponibles - Versión sin netifaces para Windows"""
        subnets = []
        try:
            # Método 1: Obtener IP local y deducir subred
            local_ip = self.get_local_ip()
            if local_ip:
                subnet_24 = self.get_subnet_from_ip(local_ip)
                if subnet_24 not in subnets:
                    subnets.append(subnet_24)
            
            # Método 2: Probar subredes comunes
            common_subnets = [
                "192.168.1.0/24", "192.168.0.0/24", "192.168.2.0/24", "192.168.3.0/24",
                "10.0.0.0/24", "10.0.1.0/24", "10.1.1.0/24", "10.1.10.0/24",
                "172.16.0.0/24", "172.16.1.0/24", "172.17.0.0/24", "172.18.0.0/24"
            ]
            
            for subnet in common_subnets:
                if subnet not in subnets:
                    subnets.append(subnet)
                    
        except Exception as e:
            self.update_status(f"Error obteniendo subredes: {e}")
            # Subred por defecto
            subnets = ["192.168.1.0/24"]
            
        return subnets
    
    def get_local_ip(self):
        """Obtiene la IP local sin usar netifaces"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return None
            
    def scan_arp(self, network):
        """Escanea la red usando ARP"""
        devices = []
        try:
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=3, verbose=0)[0]
            
            for sent, received in result:
                devices.append((received.psrc, received.hwsrc))
                
        except Exception as e:
            self.update_status(f"Error en escaneo ARP de {network}: {e}")
            
        return devices
    
    def get_device_info(self, ip):
        """Obtiene información del dispositivo usando múltiples métodos"""
        info = {
            'mac': 'Desconocida',
            'vendor': 'Desconocido',
            'model': 'Desconocido',
            'os': 'Desconocido'
        }
        
        try:
            # Intentar obtener información via Nmap
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-O -sS -T4 --host-timeout 30s')
            
            if ip in nm.all_hosts():
                host = nm[ip]
                
                # Obtener MAC address
                if 'addresses' in host and 'mac' in host['addresses']:
                    info['mac'] = host['addresses']['mac']
                    
                # Obtener fabricante
                if 'vendor' in host and info['mac'] in host['vendor']:
                    info['vendor'] = host['vendor'][info['mac']]
                
                # Obtener sistema operativo
                if 'osmatch' in host:
                    for os_match in host['osmatch']:
                        os_name = os_match['name'].lower()
                        if 'android' in os_name:
                            info['os'] = 'Android'
                            info['model'] = self.guess_android_model(info['vendor'])
                            break
                        elif 'linux' in os_name and ('phone' in os_name or 'mobile' in os_name):
                            info['os'] = 'Linux Mobile'
                        else:
                            info['os'] = os_match['name']
                
                # Si no se detectó OS, verificar puertos típicos
                if info['os'] == 'Desconocido':
                    if self.check_android_ports(ip):
                        info['os'] = 'Android (por puertos)'
                        info['model'] = self.guess_android_model(info['vendor'])
                        
        except Exception as e:
            self.update_status(f"Error Nmap para {ip}: {e}")
            
        return info
    
    def check_android_ports(self, ip):
        """Verifica puertos comunes de Android"""
        android_ports = [5555, 8080, 8000, 8888, 9000, 5037]  # ADB y servicios de desarrollo
        
        for port in android_ports[:3]:  # Revisar solo los primeros 3 para velocidad
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        return True
            except:
                continue
        return False
    
    def guess_android_model(self, vendor):
        """Intenta adivinar el modelo basado en el fabricante"""
        vendor_models = {
            'samsung': 'Samsung Galaxy',
            'xiaomi': 'Xiaomi Redmi/Note',
            'huawei': 'Huawei P/Mate',
            'oneplus': 'OnePlus',
            'google': 'Google Pixel',
            'motorola': 'Motorola Moto',
            'lg': 'LG',
            'sony': 'Sony Xperia',
            'nokia': 'Nokia',
            'oppo': 'Oppo',
            'vivo': 'Vivo',
            'realme': 'Realme'
        }
        
        if vendor.lower() in vendor_models:
            return vendor_models[vendor.lower()]
                
        return 'Dispositivo Android'
    
    def is_android_device(self, device_info):
        """Verifica si el dispositivo es Android"""
        return 'android' in device_info.get('os', '').lower()
    
    def ping_host(self, ip):
        """Verifica si el host está activo"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                result = sock.connect_ex((ip, 80))
                return result == 0 or sock.connect_ex((ip, 443)) == 0
        except:
            return False
    
    def get_local_network(self):
        """Obtiene la red local automáticamente"""
        try:
            local_ip = self.get_local_ip()
            if local_ip:
                ip_parts = local_ip.split('.')
                return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            return None
        except Exception as e:
            self.update_status(f"Error obteniendo red local: {e}")
            return None
    
    def get_subnet_from_ip(self, ip):
        """Obtiene la subred a partir de una IP"""
        try:
            ip_parts = ip.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        except:
            return "Desconocida"
    
    def validate_ip(self, ip):
        """Valida la dirección IP"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def validate_subnet(self, subnet):
        """Valida el formato de subred CIDR"""
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
        if re.match(pattern, subnet):
            ip_part, cidr_part = subnet.split('/')
            if self.validate_ip(ip_part):
                cidr = int(cidr_part)
                return 0 <= cidr <= 32
        return False
    
    def set_scanning(self, scanning):
        """Actualiza el estado de escaneo"""
        self.scanning = scanning
        self.root.after(0, self._update_scanning_ui)
        
    def _update_scanning_ui(self):
        """Actualiza la UI según el estado de escaneo"""
        if self.scanning:
            self.progress.start()
        else:
            self.progress.stop()
            
    def update_status(self, message):
        """Actualiza el mensaje de estado"""
        self.root.after(0, lambda: self.status_label.config(text=message))
        
    def clear_results(self):
        """Limpia los resultados anteriores"""
        self.root.after(0, lambda: self.results_tree.delete(*self.results_tree.get_children()))
        
    def add_result(self, ip, mac, vendor, model, os, subnet, status):
        """Agrega un resultado a la tabla"""
        self.root.after(0, lambda: self.results_tree.insert('', 'end', 
                                                          values=(ip, mac, vendor, model, os, subnet, status)))

def main():
    # Verificar si se está ejecutando como administrador
    try:
        # Intentar crear un socket (requiere privilegios para escaneo ARP)
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("⚠️  Advertencia: El programa necesita permisos de administrador para escaneo completo")
        print("   Ejecuta como administrador para mejores resultados")
    
    root = tk.Tk()
    app = AndroidDetectorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
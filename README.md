# DomainSniffer
Herramienta en Python que ejecuta envenenamiento ARP bidireccional para interceptar consultas DNS de una víctima específica y enumerar dominios solicitados en tiempo real dentro de una red LAN.


## Propósito del repositorio

Repositorio orientado a demostrar técnicas de interceptación de tráfico DNS mediante ARP spoofing en redes locales, con foco en análisis de exposición de comunicaciones sin cifrar y ataques Man-in-the-Middle en capa 2.

## Descripción técnica del script

#### Funcionalidad
Script que realiza un ataque MITM mediante ARP spoofing entre una víctima y su gateway para capturar consultas DNS (UDP/53) y mostrar los dominios solicitados, evitando duplicados y filtrando dominios comunes para reducir ruido.

#### Qué hace exactamente
- Envía paquetes ARP falsificados de forma periódica:
  - Víctima → Router  
  - Router → Víctima
- Se posiciona como intermediario del tráfico de red.
- Captura paquetes UDP en el puerto 53 usando Scapy.
- Extrae el campo `qname` de las consultas DNS.
- Muestra dominios nuevos detectados en consola.
- Aplica una blacklist básica de palabras clave para descartar tráfico irrelevante.

#### Problema de seguridad que aborda
- Ausencia de protección contra ARP spoofing en redes locales.
- Exposición de tráfico DNS en texto claro.
- Riesgo de observación de hábitos de navegación dentro de una LAN.

#### Escenarios técnicos de uso
- Pentesting de redes internas.
- Auditorías de seguridad en entornos corporativos.
- Laboratorios de ataques MITM.
- Evaluación de impacto de no usar DNS cifrado.
- Formación técnica en ataques de red.

#### Suposiciones y consideraciones
- El atacante comparte red local con la víctima.
- Ejecución con privilegios elevados.
- La red no implementa controles como Dynamic ARP Inspection o DHCP Snooping.
- El tráfico DNS no está cifrado.
- No se restauran las tablas ARP al finalizar la ejecución.
- La dirección MAC usada para el spoofing está fijada de forma estática.

---

## Ejecución y uso

### Requisitos técnicos
- Python 3.x
- Sistema Linux
- Permisos de administrador
- Dependencias:
  - `scapy`
  - `termcolor`
- Interfaz de red activa en la LAN objetivo

### Ejecución básica
<img width="1881" height="684" alt="image" src="https://github.com/user-attachments/assets/27e11af7-7e52-4fbb-9026-45955b5ca5b1" />


```bash
sudo python3 dns_arp_sniffer.py -i <interfaz> -t <ip_victima> -r <ip_router>
Parámetros:
```

`-i`: interfaz de red a utilizar.

`-t`: dirección IP de la víctima.

`-r`: dirección IP del gateway.

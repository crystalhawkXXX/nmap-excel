# 🛠️ Nmap-Excel

**Nmap-Excel** es una herramienta que realiza escaneos de red utilizando **Nmap** y genera un informe en **Excel** con los resultados obtenidos. Ideal para administradores de sistemas y profesionales de seguridad.

## 📋 Requisitos

Antes de comenzar, asegúrate de tener instalados los siguientes componentes:

- **Python 3.x**
- Biblioteca de Python: **openpyxl**

## 🚀 Instalación

Sigue estos pasos para instalar y preparar Nmap-Excel:

1. **Clona el Repositorio**:
    ```bash
    git clone https://github.com/crystalhawkXXX/nmap-excel.git
    cd nmap-excel
    ```

2. **Instala las Dependencias**:
    ```bash
    python3 -m pip install -r requirements.txt
    ```

## 🛡️ Uso

Puedes ejecutar Nmap-Excel con un solo comando. Aquí te mostramos cómo:

```bash
python3 nmap-excel.py <IP_or_Domain> <output.xlsx>

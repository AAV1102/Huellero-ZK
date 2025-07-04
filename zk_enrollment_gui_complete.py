#!/usr/bin/env python3
# Averabyte Labs – ZKTeco Genesis (GUI 2025-07-05) - Versión Completa

# ──────────────── IMPORTS ─────────────────────────────
from __future__ import annotations
import csv
import hashlib
import inspect
import logging
import os
import pathlib
import shutil
import threading
import atexit
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pyzk import ZK
from pyzk.const import USER_ADMIN, USER_DEFAULT
import pandas as pd

# ──────────────── LOGGING ─────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

# ──────────────── RUTAS Y ARCHIVOS ───────────────────
BASE_DIR = pathlib.Path.cwd() / "AVERABYTE_LABS"
BACKUP_DIR = BASE_DIR / "backups"
ATTENDANCE_DIR = BASE_DIR / "attendance_logs"
BASE_DIR.mkdir(exist_ok=True)
BACKUP_DIR.mkdir(exist_ok=True)
ATTENDANCE_DIR.mkdir(exist_ok=True)

CSV_FILE = BASE_DIR / "registro_usuarios.csv"
BITACORA = BASE_DIR / "bitacora_acciones.csv"
ACCOUNTS_FILE = BASE_DIR / "accounts.csv"
LOGO_PATH = BASE_DIR / "logo_averabyte_labs.png"
ICON_PATH = BASE_DIR / "icon_averabyte_labs.png"

# ──────────────── CONSTANTES Y CONFIG ─────────────────
SEDES: Dict[str, tuple[str, str]] = {
    "MEDELLIN": ("192.168.160.200", "K40/ID"),
    "AUTOFAX": ("192.168.162.200", "K40/ID"),
    "FONTIBON": ("192.168.163.200", "K40/ID"),
    "BARRANQUILLA": ("192.168.164.200", "K40/ID"),
    "BOGOTASUR": ("192.168.165.200", "K40/ID"),
    "VILLAVICENCIO": ("192.168.166.200", "K40/ID"),
    "ZIPAQUIRA": ("192.168.167.200", "K40/ID"),
    "PEREIRA": ("192.168.168.200", "K40/ID"),
    "DUITAMA": ("192.168.182.200", "K40/ID"),
    "CALI": ("192.168.170.200", "K40/ID"),
    "NEIVA": ("192.168.171.200", "K40/ID"),
    "IBAGUE": ("192.168.172.200", "K40/ID"),
    "BUCARAMANGA": ("192.168.173.200", "K40/ID"),
    "CARTAGENA": ("192.168.174.200", "K40/ID"),
    "MONTERIA": ("192.168.175.200", "UA300/ID"),
    "SISTEMA_V": ("192.168.176.200", "K40/ID"),
    "MOSQUERA": ("192.168.177.200", "K40/ID"),
    "CAYENA": ("192.168.178.200", "UA300/ID"),
    "20": ("192.168.180.200", "K40/ID"),
    "HATILLO": ("192.168.160.200", "K40/ID"),
    "COOWORKING": ("192.168.199.246", "UA300/ID"),
}

HEADERS: List[str] = [
    "UID", "Nombre", "C.C.", "Teléfono", "Sede", "Cargo", "Empresa",
    "Permiso", "Fingers", "Fecha Creación", "Fecha Modificación",
    "Huella Entrada", "Huella Salida", "IP"
]

PERFILES: List[str] = [
    "Super Usuario", "Admin Tipo Super Usuario",
    "Admin por Sede", "Exportador", "Usuario"
]

PERFIL_PRIV: Dict[str, int] = {
    "Super Usuario": USER_ADMIN,
    "Admin Tipo Super Usuario": USER_ADMIN,
    "Admin por Sede": USER_ADMIN,
    "Exportador": USER_DEFAULT,
    "Usuario": USER_DEFAULT,
}

PERM_RIGHTS: Dict[str, Dict[str, bool]] = {
    "Super Usuario": dict(create=True, update=True, delete=True, mark=True, export=True, lista=True, viewlog=True),
    "Admin Tipo Super Usuario": dict(create=True, update=True, delete=True, mark=True, export=True, lista=True, viewlog=True),
    "Admin por Sede": dict(create=False, update=True, delete=False, mark=True, export=True, lista=True, viewlog=True),
    "Exportador": dict(create=False, update=False, delete=False, mark=False, export=True, lista=False, viewlog=True),
    "Usuario": dict(create=False, update=False, delete=False, mark=False, export=False, lista=False, viewlog=False),
}

FINGER_NAMES: Dict[int, str] = {
    i: n for i, n in enumerate([
        "Pulgar D", "Índice D", "Medio D", "Anular D", "Meñique D",
        "Pulgar I", "Índice I", "Medio I", "Anular I", "Meñique I"
    ])
}
FINGER_OPTIONS: List[str] = [f"{i} – {FINGER_NAMES[i]}" for i in range(10)]

# ──────────────── VARIABLES GLOBALES ─────────────────
root: tk.Tk
rights: Dict[str, bool] = {}
perfil: Optional[str] = None

# Variables de la interfaz (se definirán en build_main_gui)
uid_var: tk.StringVar
nom_var: tk.StringVar
ced_var: tk.StringVar
tel_var: tk.StringVar
sede_var: tk.StringVar
cargo_var: tk.StringVar
emp_var: tk.StringVar
perm_var: tk.StringVar
finger_var: tk.StringVar
huellero_var: tk.StringVar
ip_var: tk.StringVar
search_var: tk.StringVar
vars_user: List[tk.StringVar]
ent_uid: tk.Entry
lbl_dedo: tk.Label
lbl_resumen: tk.Label

# ──────────────── VALIDACIONES ─────────────────────────
def validate_numeric_input(char: str, max_length: int = 10) -> bool:
    """Valida entrada numérica con longitud máxima."""
    if char.isdigit() and len(char) <= max_length:
        return True
    return char == ""

def validate_cc_input(char: str) -> bool:
    """Valida entrada de cédula (máximo 10 dígitos)."""
    return validate_numeric_input(char, 10)

def validate_phone_input(char: str) -> bool:
    """Valida entrada de teléfono (máximo 10 dígitos)."""
    return validate_numeric_input(char, 10)

# ──────────────── UTILIDADES CSV / BACKUP ─────────────
def sha(text: str) -> str:
    """Genera hash SHA256 de un texto."""
    return hashlib.sha256(str(text).encode()).hexdigest()

def read_csv(path: Union[str, pathlib.Path]) -> List[Dict[str, Any]]:
    """Lee un archivo CSV y retorna lista de diccionarios."""
    p = pathlib.Path(path)
    if not p.exists():
        return []
    try:
        with p.open(encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except Exception as e:
        logging.error(f"Error leyendo CSV {path}: {e}")
        return []

def write_csv(p: pathlib.Path, rows: List[Dict[str, Any]]) -> None:
    """Escribe lista de diccionarios a archivo CSV."""
    try:
        with p.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=HEADERS)
            w.writeheader()
            w.writerows(rows)
        backup_csv()
    except Exception as e:
        logging.error(f"Error escribiendo CSV {p}: {e}")

def append_row(p: pathlib.Path, row: Dict[str, Any]) -> None:
    """Añade una fila al archivo CSV."""
    try:
        empty = not p.exists()
        with p.open("a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=HEADERS)
            if empty:
                w.writeheader()
            w.writerow(row)
        backup_csv()
    except Exception as e:
        logging.error(f"Error añadiendo fila a CSV {p}: {e}")

def log(act: str, uid: str, name: str, det: str = "") -> None:
    """Registra una acción en la bitácora."""
    try:
        first = not BITACORA.exists()
        with BITACORA.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if first:
                w.writerow(["Fecha", "Acción", "UID", "Nombre", "Detalle"])
            w.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                act, uid, name, det
            ])
    except Exception as e:
        logging.error(f"Error escribiendo log: {e}")

def backup_csv() -> None:
    """Crea backup de archivos CSV."""
    try:
        stamp = datetime.now().strftime("%Y%m%d")
        for src in (CSV_FILE, BITACORA):
            if src.exists():
                dst = BACKUP_DIR / f"{src.stem}_{stamp}.csv"
                if not dst.exists():
                    shutil.copy2(src, dst)
    except Exception as e:
        logging.error(f"Error en backup: {e}")

atexit.register(backup_csv)

# ──────────────── AUTENTICACIÓN ─────────────────────────────
def ensure_default_account() -> None:
    """Crea cuenta admin por defecto si no existe."""
    if ACCOUNTS_FILE.exists():
        return
    try:
        with ACCOUNTS_FILE.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows([
                ["Usuario", "Hash", "Perfil"],
                ["admin", sha("admin123"), "Super Usuario"]
            ])
    except Exception as e:
        logging.error(f"Error creando cuenta por defecto: {e}")

def check_login(user: str, pwd: str) -> Optional[str]:
    """Verifica credenciales de login."""
    try:
        with ACCOUNTS_FILE.open(encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["Usuario"] == user and r["Hash"] == sha(pwd):
                    return r["Perfil"]
    except Exception as e:
        logging.error(f"Error verificando login: {e}")
    return None

# ──────────────── CONEXIÓN RELOJ ───────────────────────────
def zk_connect(ip: Optional[str]):
    """Conecta al dispositivo ZK."""
    if not ip:
        return None
    try:
        z = ZK(ip, port=4370, password=0, ommit_ping=True)
        conn = z.connect()
        conn.disable_device()
        return conn
    except Exception as ex:
        logging.error(f"Error conectando a {ip}: {ex}")
        return None

# ──────────────── UIDs ─────────────────────────────────────
def is_uid_in_valid_range(uid: int) -> bool:
    """Verifica si el UID está en el rango válido para el dispositivo."""
    return 1 <= uid <= 32767

def next_uid_for_sede(sede: str) -> Optional[int]:
    """Obtiene el siguiente UID disponible para una sede específica."""
    if sede not in SEDES:
        return None
    
    ip = SEDES[sede][0]
    ids = {int(r["UID"]) for r in read_csv(CSV_FILE) 
           if r["UID"].isdigit() and r["Sede"] == sede and is_uid_in_valid_range(int(r["UID"]))}
    
    conn = zk_connect(ip)
    try:
        if conn:
            users = conn.get_users()
            ids.update(int(u.uid) for u in users 
                      if str(u.uid).isdigit() and is_uid_in_valid_range(int(u.uid)))
    except Exception as e:
        logging.error(f"Error obteniendo usuarios de {sede}: {e}")
    finally:
        try:
            if conn:
                conn.enable_device()
                conn.disconnect()
        except:
            pass
    
    # Buscar el siguiente UID disponible en el rango válido
    for uid in range(1, 32768):
        if uid not in ids:
            return uid
    
    return None  # No hay UIDs disponibles

def next_uid_global() -> int:
    """Obtiene el siguiente UID global disponible."""
    ids = {int(r["UID"]) for r in read_csv(CSV_FILE) 
           if r["UID"].isdigit() and is_uid_in_valid_range(int(r["UID"]))}
    
    for ip, _ in SEDES.values():
        c = zk_connect(ip)
        try:
            if c:
                users = c.get_users()
                ids.update(int(str(u.uid)) for u in users 
                          if str(u.uid).isdigit() and is_uid_in_valid_range(int(u.uid)))
        except Exception as e:
            logging.error(f"Error obteniendo usuarios de {ip}: {e}")
        finally:
            try:
                if c:
                    if hasattr(c, "enable_device"):
                        c.enable_device()
                    c.disconnect()
            except:
                pass
    
    return next(i for i in range(1, 32768) if i not in ids)

# ──────────────── EXPORTAR ASISTENCIA ─────────────────────
def export_attendance_to_excel(sede: str) -> None:
    """Exporta registros de asistencia del dispositivo a Excel."""
    if sede not in SEDES:
        messagebox.showerror("Error", "Sede no válida")
        return
    
    ip = SEDES[sede][0]
    conn = zk_connect(ip)
    
    if not conn:
        messagebox.showerror("Error", f"No se pudo conectar al dispositivo en {sede}")
        return
    
    try:
        # Obtener registros de asistencia
        attendances = conn.get_attendance()
        
        if not attendances:
            messagebox.showinfo("Sin datos", "No hay registros de asistencia en el dispositivo")
            return
        
        # Convertir a DataFrame
        data = []
        for att in attendances:
            data.append({
                'UID': att.uid,
                'Usuario_ID': att.user_id,
                'Fecha_Hora': att.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'Fecha': att.timestamp.strftime('%Y-%m-%d'),
                'Hora': att.timestamp.strftime('%H:%M:%S'),
                'Estado': 'Entrada' if att.status == 1 else 'Salida',
                'Sede': sede,
                'IP_Dispositivo': ip
            })
        
        df = pd.DataFrame(data)
        
        # Guardar archivo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = ATTENDANCE_DIR / f"asistencia_{sede}_{timestamp}.xlsx"
        
        df.to_excel(filename, index=False, sheet_name=f'Asistencia_{sede}')
        
        messagebox.showinfo(
            "Exportación exitosa", 
            f"Registros exportados a:\n{filename}\n\nTotal registros: {len(data)}"
        )
        
        # Registrar en bitácora
        log("Exportar asistencia", "-", f"Sede {sede}", f"{len(data)} registros")
        
    except Exception as e:
        messagebox.showerror("Error", f"Error exportando asistencia: {e}")
        logging.error(f"Error exportando asistencia de {sede}: {e}")
    finally:
        try:
            conn.enable_device()
            conn.disconnect()
        except:
            pass

# ──────────────── PLACEHOLDERS EXPORTAR ────────────────────
def _show(txt: str) -> None:
    """Muestra mensaje informativo."""
    messagebox.showinfo("Aviso", txt)

def exp_reg_pdf() -> None:
    """Exportar PDF usuarios (pendiente)."""
    _show("Exportar PDF usuarios (pendiente)")

def exp_reg_xls() -> None:
    """Exportar Excel usuarios (pendiente)."""
    _show("Exportar Excel usuarios (pendiente)")

def exp_log_pdf() -> None:
    """Exportar PDF bitácora (pendiente)."""
    _show("Exportar PDF bitácora (pendiente)")

def exp_log_xls() -> None:
    """Exportar Excel bitácora (pendiente)."""
    _show("Exportar Excel bitácora (pendiente)")

def exportar_entradas_salidas() -> None:
    """Exportar entradas/salidas - Selector de sede."""
    w = tk.Toplevel(root)
    w.title("Exportar Asistencia - Seleccionar Sede")
    w.geometry("400x200")
    w.resizable(False, False)
    w.grab_set()
    
    tk.Label(w, text="Selecciona la sede para exportar asistencia:", 
             font=("Arial", 12)).pack(pady=20)
    
    sede_sel = tk.StringVar()
    cb = ttk.Combobox(
        w, textvariable=sede_sel, values=sorted(SEDES.keys()),
        state="readonly", width=30, font=("Arial", 10)
    )
    cb.pack(pady=10)
    cb.focus_set()
    
    def exportar():
        sede = sede_sel.get()
        if not sede:
            messagebox.showwarning("Sede", "Debes seleccionar una sede")
            return
        w.destroy()
        export_attendance_to_excel(sede)
    
    btn_frame = tk.Frame(w)
    btn_frame.pack(pady=20)
    
    tk.Button(btn_frame, text="Exportar", command=exportar, 
              bg="#4CAF50", fg="white", font=("Arial", 10)).pack(side="left", padx=10)
    tk.Button(btn_frame, text="Cancelar", command=w.destroy, 
              bg="#f44336", fg="white", font=("Arial", 10)).pack(side="left", padx=10)

def ver_log() -> None:
    """Visor bitácora (pendiente)."""
    _show("Visor bitácora (pendiente)")

# ──────────────── LOGIN GUI ────────────────────────────────
def show_login() -> None:
    """Muestra ventana de login."""
    dlg = tk.Toplevel(root)
    dlg.title("Login – Averabyte Labs")
    dlg.grab_set()
    dlg.resizable(False, False)

    tk.Label(dlg, text="Usuario").grid(row=0, column=0, padx=6, pady=4)
    tk.Label(dlg, text="Contraseña").grid(row=1, column=0)

    usr = tk.StringVar()
    pwd = tk.StringVar()
    tk.Entry(dlg, textvariable=usr).grid(row=0, column=1)
    tk.Entry(dlg, textvariable=pwd, show="*").grid(row=1, column=1)

    def ingresar() -> None:
        perfil_login = check_login(usr.get(), pwd.get())
        if not perfil_login:
            messagebox.showerror("Login", "Credenciales inválidas")
            return
        dlg.destroy()
        build_main_gui(perfil_login)

    tk.Button(dlg, text="Ingresar", command=ingresar).grid(
        row=2, column=0, columnspan=2, pady=6
    )

# ──────────────── FUNCIONES DE LA GUI ─────────────────────
def msg(f: Callable, *a: Any, **k: Any) -> None:
    """Helper para invocar diálogos desde hilos."""
    root.after(0, lambda: f(*a, **k))

def on_sede_selected(_: Any = None) -> None:
    """Maneja selección de sede."""
    sede = sede_var.get()
    if sede in SEDES:
        huellero_var.set(SEDES[sede][1])
        ip_var.set(SEDES[sede][0])
    else:
        huellero_var.set("")
        ip_var.set("")

def on_finger(*_: Any) -> None:
    """Maneja selección de dedo."""
    lbl_dedo.config(text=finger_var.get())

def clear_form() -> None:
    """Limpia el formulario."""
    for v in vars_user + [perm_var, finger_var, huellero_var, ip_var]:
        v.set("")
    finger_var.set(FINGER_OPTIONS[0])
    on_finger()
    ent_uid.config(state="normal")

def nuevo() -> None:
    """Prepara formulario para nuevo usuario."""
    clear_form()
    
    # Obtener UID específico para la sede seleccionada o global
    sede_actual = sede_var.get()
    if sede_actual and sede_actual in SEDES:
        next_uid = next_uid_for_sede(sede_actual)
        if next_uid is None:
            messagebox.showerror("Error", f"No hay UIDs disponibles en la sede {sede_actual}")
            return
    else:
        next_uid = next_uid_global()
    
    uid_var.set(str(next_uid))
    ent_uid.config(state="normal")  # Permitir edición manual del UID
    
    if perfil in ("Super Usuario", "Admin Tipo Super Usuario"):
        on_sede_selected()

def buscar() -> None:
    """Busca usuario por UID o C.C."""
    q = search_var.get().strip().lower()
    if not q:
        return

    # 1) Buscar en CSV
    rows = read_csv(CSV_FILE)
    reg = next((r for r in rows
                if q in str(r["UID"]).lower() or q in str(r["C.C."]).lower()),
               None)
    
    if reg:
        uid_var.set(reg["UID"])
        nom_var.set(reg["Nombre"])
        ced_var.set(reg["C.C."])
        tel_var.set(reg["Teléfono"])
        sede_var.set(reg["Sede"])
        cargo_var.set(reg["Cargo"])
        emp_var.set(reg["Empresa"])
        perm_var.set(reg["Permiso"])
        huellero_var.set(reg.get("Huellero", SEDES.get(reg["Sede"], ("", ""))[1]))
        ip_var.set(reg.get("IP", SEDES.get(reg["Sede"], ("", ""))[0]))

        # Dedo por defecto
        if reg["Fingers"]:
            d = reg["Fingers"].split(";")[0]
            finger_var.set(f"{d} – {FINGER_NAMES[int(d)]}")
        else:
            finger_var.set(FINGER_OPTIONS[0])

        on_finger()
        ent_uid.config(state="normal")  # Permitir edición del UID
        return

    # 2) Usuario no está en CSV → preguntar sede para buscar / crear
    w = tk.Toplevel(root)
    w.title("Selecciona sede")
    sel = tk.StringVar()

    ttk.Combobox(
        w, textvariable=sel, values=sorted(SEDES.keys()),
        state="readonly", width=30
    ).grid(row=0, column=0, padx=8, pady=8)

    def continuar() -> None:
        sede = sel.get()
        if not sede:
            messagebox.showwarning("Sede", "Selecciona sede")
            return

        ip = SEDES[sede][0]
        conn = zk_connect(ip)
        found = None

        if conn:
            try:
                for u in conn.get_users():
                    if q in str(u.uid).lower() or q in str(u.user_id).lower():
                        found = u
                        break
            except Exception as e:
                logging.error(f"Error buscando en dispositivo: {e}")
            finally:
                try:
                    conn.enable_device()
                    conn.disconnect()
                except:
                    pass

        if found:
            uid_var.set(str(found.uid))
            nom_var.set(found.name)
            ced_var.set(str(found.user_id))
            sede_var.set(sede)
            huellero_var.set(SEDES[sede][1])
            ip_var.set(ip)
            ent_uid.config(state="normal")  # Permitir edición del UID
            messagebox.showinfo(
                "Dispositivo",
                "Existe en reloj; completa datos y guarda."
            )
        else:
            clear_form()
            ced_var.set(q if q.isdigit() else "")
            sede_var.set(sede)
            huellero_var.set(SEDES[sede][1])
            ip_var.set(ip)
            perm_var.set("Usuario")

            nxt = next_uid_for_sede(sede)
            if nxt is None:
                messagebox.showerror("UID", f"Reloj {sede} lleno (32767).")
                w.destroy()
                return

            uid_var.set(str(nxt))
            ent_uid.config(state="normal")  # Permitir edición del UID
            messagebox.showinfo(
                "Nuevo",
                "Ingresa datos y pulsa Guardar / Enrolar."
            )
        w.destroy()

    tk.Button(w, text="Continuar", command=continuar).grid(
        row=1, column=0, pady=8
    )

def listar_disp() -> None:
    """Lista usuarios del dispositivo con barras de desplazamiento."""
    if not rights.get("lista", False):
        return

    w = tk.Toplevel(root)
    w.title("Selecciona sede")
    sede_sel = tk.StringVar()

    ttk.Combobox(
        w, textvariable=sede_sel, values=sorted(SEDES.keys()),
        state="readonly", width=30
    ).grid(row=0, column=0, padx=8, pady=8)

    def mostrar() -> None:
        sede = sede_sel.get()
        if not sede:
            msg(messagebox.showwarning, "Sede", "Selecciona sede")
            return
        ip = SEDES[sede][0]

        def leer_dispositivo():
            try:
                conn = zk_connect(ip)
                if not conn:
                    raise Exception("Sin conexión")
                return conn.get_users()
            except Exception as e:
                raise e
            finally:
                try:
                    if conn:
                        conn.enable_device()
                        conn.disconnect()
                except:
                    pass

        try:
            dev_users = leer_dispositivo()
        except Exception as e:
            msg(messagebox.showerror, "Error", str(e))
            return
        
        w.destroy()

        # Ventana principal con barras de desplazamiento
        win = tk.Toplevel(root)
        win.title(f"Usuarios en {sede}")
        win.geometry("1200x600")
        
        # Frame principal con scrollbars
        main_frame = tk.Frame(win)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Crear canvas y scrollbars
        canvas = tk.Canvas(main_frame)
        v_scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(main_frame, orient="horizontal", command=canvas.xview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Tabla con todas las columnas incluyendo las faltantes
        rows_local = {r["UID"]: r for r in read_csv(CSV_FILE)}
        cols = [
            "UID", "Cédula", "Nombre", "Teléfono", "Sede", "Cargo", "Empresa",
            "Permiso", "Huellero", "IP", "Dedo"
        ]

        tv = ttk.Treeview(scrollable_frame, columns=cols, show="headings", height=20)
        for c in cols:
            tv.heading(c, text=c)
            tv.column(c, anchor="center", width=120)
        
        tv.pack(fill="both", expand=True)

        # Filtro + botón actualizar
        barra = tk.Frame(win)
        barra.pack(fill="x", pady=2)
        filtro = tk.StringVar()
        tk.Label(barra, text="Filtrar:").pack(side="left")
        tk.Entry(barra, textvariable=filtro, width=20).pack(side="left", padx=4)

        def refrescar(*_: Any) -> None:
            try:
                tv.delete(*tv.get_children())
            except tk.TclError:
                return
                
            pattern = filtro.get().lower()
            rows_local.clear()
            rows_local.update({r["UID"]: r for r in read_csv(CSV_FILE)})

            for u in dev_users:
                uid = str(u.uid)
                reg = rows_local.get(uid, {})
                dedo = reg.get("Fingers", "0").split(";")[0]
                try:
                    dedo_int = int(dedo)
                except ValueError:
                    dedo_int = 0
                
                fila = [
                    uid, str(u.user_id), u.name, 
                    reg.get("Teléfono", ""), sede,
                    reg.get("Cargo", ""), reg.get("Empresa", ""),
                    reg.get("Permiso", ""), SEDES[sede][1], SEDES[sede][0],
                    f"{dedo} – {FINGER_NAMES.get(dedo_int, 'Desconocido')}"
                ]
                if pattern and not any(pattern in str(x).lower() for x in fila):
                    continue
                
                try:
                    tv.insert("", "end", values=fila)
                except tk.TclError:
                    return

        def actualizar_dispositivo() -> None:
            nonlocal dev_users
            try:
                if not win.winfo_exists():
                    return
                dev_users = leer_dispositivo()
            except Exception as e:
                msg(messagebox.showerror, "Error", str(e))
                return
            refrescar()

        ttk.Button(barra, text="🔄 Actualizar",
                   command=actualizar_dispositivo).pack(side="left", padx=4)

        filtro.trace_add("write", refrescar)
        refrescar()

        def sel(_evt: Any) -> None:
            it = tv.focus()
            if not it:
                return
            v = tv.item(it, "values")
            if len(v) >= 11:
                uid_var.set(v[0])
                ced_var.set(v[1])
                nom_var.set(v[2])
                tel_var.set(v[3])
                sede_var.set(v[4])
                cargo_var.set(v[5])
                emp_var.set(v[6])
                perm_var.set(v[7])
                huellero_var.set(v[8])
                ip_var.set(v[9])
                finger_var.set(v[10])
                on_finger()
                ent_uid.config(state="normal")  # Permitir edición del UID
                win.destroy()

        tv.bind("<Double-1>", sel)
        
        # Configurar scrollbars
        canvas.pack(side="left", fill="both", expand=True)
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")

        def safe_refresh():
            try:
                if win.winfo_exists():
                    actualizar_dispositivo()
            except tk.TclError:
                if hasattr(root, "current_list_refresh"):
                    delattr(root, "current_list_refresh")

        setattr(root, "current_list_refresh", safe_refresh)

        def on_close():
            if hasattr(root, "current_list_refresh"):
                delattr(root, "current_list_refresh")
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

    tk.Button(w, text="Mostrar", command=mostrar).grid(row=1, column=0, pady=8)

def marcar(tipo: str) -> None:
    """Marca entrada o salida directamente en el dispositivo y exporta a Excel."""
    if perfil == "Usuario":
        msg(messagebox.showinfo, "Marcación", "Sin permisos")
        return
    
    uid = uid_var.get().strip()
    cc = str(ced_var.get()).strip()
    ip = ip_var.get().strip()
    sede = sede_var.get().strip()
    
    if not ip or not sede:
        msg(messagebox.showerror, "Error", "Debe seleccionar una sede válida")
        return
    
    if not uid and not cc:
        msg(messagebox.showerror, "Error", "Debe ingresar UID o Cédula")
        return
    
    conn = zk_connect(ip)
    if not conn:
        msg(messagebox.showerror, "Error", f"No se pudo conectar al dispositivo en {sede}")
        return
    
    try:
        # Buscar usuario en el dispositivo
        users = conn.get_users()
        target_user = None
        
        for u in users:
            if (uid and str(u.uid) == uid) or (cc and str(u.user_id) == cc):
                target_user = u
                break
        
        if not target_user:
            msg(messagebox.showerror, "Error", "Usuario no encontrado en el dispositivo")
            return
        
        # Crear registro de asistencia manual
        now = datetime.now()
        status = 1 if tipo == "entrada" else 0  # 1 = entrada, 0 = salida
        
        # Intentar crear el registro en el dispositivo
        try:
            # Algunos dispositivos permiten insertar registros de asistencia
            conn.set_attendance(uid=target_user.uid, timestamp=now, status=status)
            device_success = True
        except Exception as e:
            logging.warning(f"No se pudo registrar en dispositivo: {e}")
            device_success = False
        
        # Crear archivo Excel con el registro
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")
        filename = ATTENDANCE_DIR / f"marcacion_manual_{sede}_{timestamp_str}.xlsx"
        
        data = [{
            'UID': target_user.uid,
            'Usuario_ID': target_user.user_id,
            'Nombre': target_user.name,
            'Fecha_Hora': now.strftime('%Y-%m-%d %H:%M:%S'),
            'Fecha': now.strftime('%Y-%m-%d'),
            'Hora': now.strftime('%H:%M:%S'),
            'Estado': 'Entrada' if tipo == "entrada" else 'Salida',
            'Sede': sede,
            'IP_Dispositivo': ip,
            'Tipo_Registro': 'Manual',
            'Registrado_Por': perfil
        }]
        
        df = pd.DataFrame(data)
        df.to_excel(filename, index=False, sheet_name=f'Marcacion_{sede}')
        
        # Actualizar CSV local si existe el usuario
        rows = read_csv(CSV_FILE)
        csv_updated = False
        for r in rows:
            if r["UID"] == str(target_user.uid) or str(r["C.C."]) == str(target_user.user_id):
                if tipo == "entrada":
                    r["Huella Entrada"] = now.strftime("%Y-%m-%d %H:%M:%S")
                    accion = "Entrada"
                elif tipo == "salida":
                    r["Huella Salida"] = now.strftime("%Y-%m-%d %H:%M:%S")
                    accion = "Salida"
                
                write_csv(CSV_FILE, rows)
                csv_updated = True
                break
        
        # Registrar en bitácora
        log(f"Marcar {tipo}", str(target_user.uid), target_user.name, f"Manual - {sede}")
        
        # Mensaje de confirmación
        status_msg = []
        if device_success:
            status_msg.append("✅ Registrado en dispositivo")
        else:
            status_msg.append("⚠️ No se pudo registrar en dispositivo")
        
        status_msg.append(f"✅ Exportado a Excel: {filename.name}")
        
        if csv_updated:
            status_msg.append("✅ Actualizado en CSV local")
        else:
            status_msg.append("⚠️ Usuario no encontrado en CSV local")
        
        msg(messagebox.showinfo, "Marcación Completada", "\n".join(status_msg))
        clear_form()
        
    except Exception as e:
        msg(messagebox.showerror, "Error", f"Error en marcación: {e}")
        logging.error(f"Error en marcación {tipo}: {e}")
    finally:
        try:
            conn.enable_device()
            conn.disconnect()
        except:
            pass

def enrolar(uid: str, fid: str) -> bool:
    """Enrola huella en el dispositivo con confirmación visual."""
    ip = ip_var.get()
    fid_n = fid.split("–")[0].strip()
    
    if not ip:
        msg(messagebox.showerror, "Conexión", "Sin IP")
        return False
    
    try:
        fid_int = int(fid_n)
        uid_int = int(uid)
    except ValueError:
        msg(messagebox.showerror, "Error", "UID o dedo inválido")
        return False
    
    # Verificar rango de UID
    if not (1 <= uid_int <= 65535):  # Rango extendido para permitir modificaciones
        msg(messagebox.showerror, "Error", "UID debe estar entre 1 y 65535")
        return False
    
    finger_name = FINGER_NAMES.get(fid_int, 'dedo')
    msg(messagebox.showinfo, "Enrolar", 
        f"Coloque {finger_name} en el sensor 3 veces\n\n"
        f"UID: {uid}\n"
        f"Usuario: {nom_var.get()}\n"
        f"Cédula: {ced_var.get()}")
    
    conn = zk_connect(ip)
    if not conn:
        msg(messagebox.showerror, "Error", "No se pudo conectar al dispositivo")
        return False
    
    try:
        # Verificar si el UID ya existe y eliminarlo si es necesario
        existing_users = conn.get_users()
        for existing_user in existing_users:
            if existing_user.uid == uid_int:
                try:
                    conn.delete_user(uid=uid_int)
                    logging.info(f"Usuario existente con UID {uid_int} eliminado para re-enrolar")
                except Exception as e:
                    logging.warning(f"No se pudo eliminar usuario existente: {e}")
        
        # Enrolar huella
        sig = inspect.signature(conn.enroll_user)
        kw = {"uid": uid_int, "user_id": str(ced_var.get())}
        
        if "finger" in sig.parameters:
            kw["finger"] = fid_int
        elif "fid" in sig.parameters:
            kw["fid"] = fid_int
        
        conn.enroll_user(**kw)
        
        # Verificar que la huella se enroló correctamente
        enrollment_success = False
        try:
            # Intentar obtener el template para verificar
            tpl = conn.get_user_template(uid=uid_int, fid=fid_int)
            enrollment_success = bool(tpl and len(tpl) > 0)
        except Exception as e:
            logging.warning(f"No se pudo verificar template: {e}")
            # Si no se puede verificar, asumir que funcionó
            enrollment_success = True
        
        if not enrollment_success:
            msg(messagebox.showerror, "Error", 
                "No se detectó la huella correctamente.\n"
                "Por favor, intente nuevamente asegurándose de:\n"
                "1. Colocar el dedo firmemente en el sensor\n"
                "2. Mantener el dedo inmóvil durante la lectura\n"
                "3. Repetir el proceso 3 veces")
            try:
                conn.delete_user(uid=uid_int)
            except:
                pass
            return False
        
        # Configurar usuario con privilegios
        priv = 0 if perm_var.get() == "Usuario" else PERFIL_PRIV.get(perm_var.get(), 0)
        
        # Usar el nombre ingresado, no generar automáticamente
        user_name = str(nom_var.get()).strip()
        if not user_name:
            user_name = f"Usuario_{uid_int}"
        
        conn.set_user(
            uid=uid_int, 
            user_id=str(ced_var.get()),
            name=user_name[:24],  # Límite de caracteres del dispositivo
            privilege=int(priv), 
            group_id=1
        )
        
        msg(messagebox.showinfo, "Éxito", 
            f"✅ Huella enrolada exitosamente!\n\n"
            f"UID: {uid_int}\n"
            f"Nombre: {user_name}\n"
            f"Dedo: {finger_name}\n"
            f"Dispositivo: {ip}")
        
        return True
        
    except Exception as e:
        error_msg = str(e)
        if "format requires" in error_msg and "32767" in error_msg:
            msg(messagebox.showerror, "Error de Rango", 
                f"El UID {uid_int} está fuera del rango soportado por el dispositivo (1-32767).\n"
                f"El usuario se guardará solo en el CSV local.")
            return False
        else:
            msg(messagebox.showerror, "Error", f"Error durante el enrolamiento: {error_msg}")
            return False
    finally:
        try:
            conn.enable_device()
            conn.disconnect()
        except:
            pass

def guardar() -> None:
    """Guarda/enrola usuario con UID editable."""
    if not rights.get("create", False):
        return
    
    uid = uid_var.get().strip()
    fid = finger_var.get().split("–")[0].strip()
    
    if not uid.isdigit():
        messagebox.showerror("UID", "El UID debe ser numérico")
        return
        
    uid_int = int(uid)
    if not (1 <= uid_int <= 65535):
        messagebox.showerror("UID", "El UID debe estar entre 1 y 65535")
        return
    
    # Validar campos obligatorios
    if not nom_var.get().strip():
        messagebox.showerror("Error", "El nombre es obligatorio")
        return
    
    if not ced_var.get().strip():
        messagebox.showerror("Error", "La cédula es obligatoria")
        return
    
    rows = read_csv(CSV_FILE)
    reg = next((r for r in rows if r["UID"] == uid), None)
    
    def worker() -> None:
        if reg:
            # Usuario existente - añadir dedo
            fingers = reg["Fingers"].split(";") if reg["Fingers"] else []
            if fid in fingers:
                msg(messagebox.showwarning, "Duplicado", "Dedo ya existe")
                return
            
            # Intentar enrolar en dispositivo
            device_success = False
            if is_uid_in_valid_range(uid_int):
                device_success = enrolar(uid, fid)
            
            if device_success or not is_uid_in_valid_range(uid_int):
                fingers.append(fid)
                reg["Fingers"] = ";".join(fingers)
                reg["Nombre"] = nom_var.get()  # Actualizar nombre
                write_csv(CSV_FILE, rows)
                log("Enrolar dedo extra", uid, reg["Nombre"])
                
                if is_uid_in_valid_range(uid_int):
                    msg(messagebox.showinfo, "OK", "Dedo añadido en dispositivo y CSV")
                else:
                    msg(messagebox.showinfo, "OK", "Dedo añadido en CSV (UID fuera de rango del dispositivo)")
                
                clear_form()
            return
        
        # Usuario nuevo
        if any(not v.get().strip() for v in [uid_var, nom_var, ced_var, sede_var]):
            msg(messagebox.showerror, "Datos", "Completa los campos obligatorios: UID, Nombre, Cédula, Sede")
            return
        
        # Intentar enrolar en dispositivo si está en rango válido
        device_success = False
        if is_uid_in_valid_range(uid_int):
            device_success = enrolar(uid, fid)
        
        # Guardar en CSV independientemente del resultado del dispositivo
        fila = dict(zip(HEADERS, [
            uid, nom_var.get(), ced_var.get(), tel_var.get(),
            sede_var.get(), cargo_var.get(), emp_var.get(),
            perm_var.get(), fid,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "", "", "", ip_var.get()
        ]))
        
        append_row(CSV_FILE, fila)
        log("Crear", uid, nom_var.get())
        
        if is_uid_in_valid_range(uid_int):
            if device_success:
                msg(messagebox.showinfo, "OK", "Usuario creado y enrolado en dispositivo")
            else:
                msg(messagebox.showinfo, "Parcial", "Usuario guardado en CSV, pero falló enrolamiento en dispositivo")
        else:
            msg(messagebox.showinfo, "OK", "Usuario guardado en CSV (UID fuera de rango del dispositivo)")
        
        clear_form()
    
    threading.Thread(target=worker).start()

def actualizar() -> None:
    """Actualiza usuario existente con UID editable."""
    if not rights.get("update", False):
        return
    
    uid = uid_var.get().strip()
    if not uid.isdigit():
        messagebox.showerror("UID", "El UID debe ser numérico")
        return
        
    uid_int = int(uid)
    if not (1 <= uid_int <= 65535):
        messagebox.showerror("UID", "El UID debe estar entre 1 y 65535")
        return
    
    # Actualizar en dispositivo si está en rango válido
    device_success = False
    if is_uid_in_valid_range(uid_int):
        conn = zk_connect(ip_var.get())
        if conn:
            try:
                priv = PERFIL_PRIV.get(perm_var.get(), 0)
                user_name = str(nom_var.get()).strip()
                if not user_name:
                    user_name = f"Usuario_{uid_int}"
                
                conn.set_user(
                    uid=uid_int, user_id=str(ced_var.get()),
                    name=user_name[:24],
                    privilege=int(priv), group_id=1
                )
                device_success = True
            except Exception as e:
                logging.error(f"Error actualizando en dispositivo: {e}")
                msg(messagebox.showwarning, "Advertencia", f"Error actualizando en dispositivo: {e}")
            finally:
                try:
                    conn.enable_device()
                    conn.disconnect()
                except:
                    pass
    
    # Actualizar en CSV
    rows = read_csv(CSV_FILE)
    csv_updated = False
    for r in rows:
        if r["UID"] == uid:
            r.update({
                "Nombre": nom_var.get(),
                "C.C.": ced_var.get(),
                "Teléfono": tel_var.get(),
                "Sede": sede_var.get(),
                "Cargo": cargo_var.get(),
                "Empresa": emp_var.get(),
                "Permiso": perm_var.get(),
                "Fecha Modificación": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "IP": ip_var.get()
            })
            csv_updated = True
            break
    
    if csv_updated:
        write_csv(CSV_FILE, rows)
        log("Actualizar", uid, nom_var.get())
        
        if is_uid_in_valid_range(uid_int):
            if device_success:
                msg(messagebox.showinfo, "OK", "Usuario actualizado en dispositivo y CSV")
            else:
                msg(messagebox.showinfo, "Parcial", "Usuario actualizado en CSV, pero falló actualización en dispositivo")
        else:
            msg(messagebox.showinfo, "OK", "Usuario actualizado en CSV (UID fuera de rango del dispositivo)")
        
        clear_form()
    else:
        msg(messagebox.showerror, "Error", "Usuario no encontrado en CSV")

def eliminar() -> None:
    """Elimina usuario por cédula o UID (incluyendo fuera de rango)."""
    if not rights.get("delete", False):
        return

    uid_txt = uid_var.get().strip()
    cc_txt = str(ced_var.get()).strip()

    # Determinar modo de eliminación
    if uid_txt.isdigit():
        uid_int = int(uid_txt)
        if uid_int > 32767:
            # UID fuera de rango - solo eliminar de CSV
            llave = uid_txt
            pregunta = f"Eliminar usuario con UID {llave} (fuera de rango del dispositivo)?\nSolo se eliminará del CSV local."
            eliminar_de_dispositivo = False
            modo_uid_fuera_rango = True
        else:
            # UID en rango - eliminar de dispositivo y CSV
            if not cc_txt:
                messagebox.showerror("Eliminar", "Ingresa la cédula para eliminar del dispositivo")
                return
            llave = cc_txt
            pregunta = f"Eliminar usuario con cédula {llave}?"
            eliminar_de_dispositivo = True
            modo_uid_fuera_rango = False
    else:
        if not cc_txt:
            messagebox.showerror("Eliminar", "Ingresa la cédula")
            return
        llave = cc_txt
        pregunta = f"Eliminar usuario con cédula {llave}?"
        eliminar_de_dispositivo = True
        modo_uid_fuera_rango = False

    if not messagebox.askyesno("Confirmar", pregunta):
        return

    # Eliminar del dispositivo si corresponde
    if eliminar_de_dispositivo:
        conn = zk_connect(ip_var.get())
        try:
            if conn:
                for u in conn.get_users():
                    if str(u.user_id) == cc_txt:
                        if is_uid_in_valid_range(int(u.uid)):
                            conn.delete_user(uid=int(u.uid))
                            logging.info(f"Usuario eliminado del dispositivo: UID {u.uid}, Cédula {cc_txt}")
                        else:
                            logging.warning(f"UID {u.uid} fuera de rango, no se puede eliminar del dispositivo")
                        break
        except Exception as e:
            logging.error(f"Error eliminando del dispositivo: {e}")
        finally:
            if conn:
                try:
                    conn.enable_device()
                    conn.disconnect()
                except:
                    pass

    # Eliminar del CSV
    rows = read_csv(CSV_FILE)
    if modo_uid_fuera_rango:
        rows_filtradas = [r for r in rows if r["UID"] != uid_txt]
        log("Eliminar por UID fuera de rango", uid_txt, "")
    else:
        rows_filtradas = [r for r in rows if str(r["C.C."]) != cc_txt]
        log("Eliminar por cédula", "", cc_txt)

    write_csv(CSV_FILE, rows_filtradas)
    
    if modo_uid_fuera_rango:
        msg(messagebox.showinfo, "OK", "Usuario eliminado del CSV (UID fuera de rango del dispositivo)")
    else:
        msg(messagebox.showinfo, "OK", "Usuario eliminado del dispositivo y CSV")
    
    clear_form()

    # Actualizar lista si está abierta
    if hasattr(root, "current_list_refresh") and callable(getattr(root, "current_list_refresh")):
        try:
            getattr(root, "current_list_refresh")()
        except tk.TclError:
            delattr(root, "current_list_refresh")

def actualizar_resumen(mensaje: Optional[str] = None) -> None:
    """Actualiza el resumen en la interfaz."""
    try:
        registros = read_csv(CSV_FILE)
        total = len(registros)
        
        # Separar UIDs válidos e inválidos
        uids_validos = [int(r["UID"]) for r in registros 
                       if r["UID"].isdigit() and is_uid_in_valid_range(int(r["UID"]))]
        uids_fuera_rango = [int(r["UID"]) for r in registros 
                           if r["UID"].isdigit() and not is_uid_in_valid_range(int(r["UID"]))]
        
        ultimo_uid_valido = max(uids_validos) if uids_validos else 0
        fuera_rango_count = len(uids_fuera_rango)
        
        if CSV_FILE.exists():
            fecha_mod = datetime.fromtimestamp(
                os.path.getmtime(CSV_FILE)
            ).strftime("%Y-%m-%d %H:%M:%S")
        else:
            fecha_mod = "N/A"

        resumen_txt = (
            f"🧾 Total usuarios: {total}  |  Último UID válido: {ultimo_uid_valido}  "
            f"|  Fuera de rango: {fuera_rango_count}  |  CSV modificado: {fecha_mod}"
        )
        
        if mensaje:
            resumen_txt += f"  |  Última acción: {mensaje}"
            log("Resumen", "-", "-", mensaje)

        lbl_resumen.config(text=resumen_txt)

    except Exception as e:
        lbl_resumen.config(text=f"⚠️ Error leyendo CSV: {e}")

# ──────────────── GUI PRINCIPAL ─────────────────────────────
def build_main_gui(perfil_param: str) -> None:
    """Genera la ventana principal según el perfil recibido."""
    global root, rights, perfil
    global uid_var, nom_var, ced_var, tel_var, sede_var, cargo_var, emp_var
    global perm_var, finger_var, huellero_var, ip_var, search_var, vars_user
    global ent_uid, lbl_dedo, lbl_resumen
    
    perfil = perfil_param
    rights = PERM_RIGHTS.get(perfil, {})

    if not rights:
        messagebox.showerror("Error", "Perfil no reconocido")
        root.destroy()
        return

    # --- Construcción de interfaz ---
    root.deiconify()
    root.title(f"Averabyte Labs – ZKTeco Genesis  ({perfil})")
    
    # Logo
    if LOGO_PATH.exists():
        try:
            img = tk.PhotoImage(file=str(LOGO_PATH))
            lbl = tk.Label(root, image=img)
            setattr(lbl, '_image_ref', img)
            lbl.grid(row=0, column=0, rowspan=3, padx=4)
        except tk.TclError:
            pass
    
    # Icono
    if ICON_PATH.exists():
        try:
            root.iconphoto(False, tk.PhotoImage(file=str(ICON_PATH)))
        except tk.TclError:
            pass

    # Botones superiores
    btn_list = tk.Button(root, text="📋 Lista disp.", command=listar_disp)
    btn_nuevo = tk.Button(root, text="➕ Nuevo", bg="#8bc34a", fg="white",
                          width=10, command=nuevo)
    
    search_var = tk.StringVar()
    tk.Label(root, text="Buscar UID/C.C.").grid(row=0, column=2, sticky="e")
    tk.Entry(root, textvariable=search_var, width=18).grid(row=0, column=3)
    tk.Button(root, text="Buscar", command=buscar).grid(row=0, column=4, padx=2)
    btn_list.grid(row=0, column=1, padx=2, pady=6)
    btn_nuevo.grid(row=0, column=6, padx=2)

    # Variables del formulario
    labels = ["UID", "Nombre", "C.C.", "Teléfono", "Sede", "Cargo", "Empresa", "Permiso"]
    uid_var = tk.StringVar()
    nom_var = tk.StringVar()
    ced_var = tk.StringVar()
    tel_var = tk.StringVar()
    sede_var = tk.StringVar()
    cargo_var = tk.StringVar()
    emp_var = tk.StringVar()
    perm_var = tk.StringVar(value=PERFILES[-1])
    finger_var = tk.StringVar(value=FINGER_OPTIONS[0])
    huellero_var = tk.StringVar()
    ip_var = tk.StringVar()
    
    vars_user = [uid_var, nom_var, ced_var, tel_var, sede_var, cargo_var, emp_var]

    # Registrar validaciones
    vcmd_cc = (root.register(validate_cc_input), '%P')
    vcmd_phone = (root.register(validate_phone_input), '%P')

    # Campos del formulario
    row = 1
    for lbl, var in zip(labels, vars_user + [perm_var]):
        tk.Label(root, text=lbl).grid(row=row, column=1, sticky="e")
        
        if lbl == "Permiso":
            ttk.Combobox(
                root, textvariable=perm_var, values=PERFILES,
                state="readonly", width=33
            ).grid(row=row, column=2, columnspan=3, padx=2, pady=1)
        elif lbl == "Sede":
            if perfil in ("Super Usuario", "Admin Tipo Super Usuario"):
                cb = ttk.Combobox(
                    root, textvariable=sede_var,
                    values=sorted(SEDES.keys()), state="readonly", width=33
                )
                cb.grid(row=row, column=2, columnspan=3, padx=2, pady=1)
                cb.bind("<<ComboboxSelected>>", on_sede_selected)
            else:
                sede_var.set("COOWORKING")
                huellero_var.set(SEDES["COOWORKING"][1])
                ip_var.set(SEDES["COOWORKING"][0])
                tk.Entry(
                    root, textvariable=sede_var, state="readonly", width=35
                ).grid(row=row, column=2, columnspan=3, padx=2, pady=1)
        else:
            # Aplicar validaciones a campos específicos
            if lbl == "C.C.":
                e = tk.Entry(root, textvariable=var, width=35, validate='key', validatecommand=vcmd_cc)
            elif lbl == "Teléfono":
                e = tk.Entry(root, textvariable=var, width=35, validate='key', validatecommand=vcmd_phone)
            else:
                e = tk.Entry(root, textvariable=var, width=35)
            
            e.grid(row=row, column=2, columnspan=3, padx=2, pady=1)
            if lbl == "UID":
                ent_uid = e
        row += 1

    # Campos adicionales
    tk.Label(root, text="Huellero").grid(row=row, column=1, sticky="e")
    tk.Entry(root, textvariable=huellero_var, state="readonly", width=35).grid(
        row=row, column=2, columnspan=3, padx=2, pady=1
    )
    row += 1
    
    tk.Label(root, text="IP").grid(row=row, column=1, sticky="e")
    tk.Entry(root, textvariable=ip_var, state="readonly", width=35).grid(
        row=row, column=2, columnspan=3, padx=2, pady=1
    )
    row += 1
    
    tk.Label(root, text="Dedo").grid(row=row, column=1, sticky="e")
    ttk.Combobox(
        root, textvariable=finger_var, values=FINGER_OPTIONS,
        state="readonly", width=15
    ).grid(row=row, column=2, sticky="w")
    
    lbl_dedo = tk.Label(root, text=FINGER_OPTIONS[0])
    lbl_dedo.grid(row=row, column=3, columnspan=2, sticky="w")
    finger_var.trace_add("write", on_finger)
    row += 1

    # Botones de acción principales
    btn_save = tk.Button(
        root, text="💾 Guardar / Enrolar", bg="#4caf50",
        fg="white", width=18, command=guardar
    )
    btn_update = tk.Button(
        root, text="Actualizar", bg="#2196f3",
        fg="white", width=12, command=actualizar
    )
    btn_del = tk.Button(
        root, text="Eliminar por Cédula", command=eliminar,
        bg="red", fg="white"
    )
    btn_in = tk.Button(
        root, text="Marcar Entrada", bg="#009688",
        fg="white", width=14, command=lambda: marcar("entrada")
    )
    btn_out = tk.Button(
        root, text="Marcar Salida", bg="#ff9800",
        fg="white", width=14, command=lambda: marcar("salida")
    )
    btn_clear = tk.Button(root, text="Limpiar", width=10, command=clear_form)

    btn_save.grid(row=row, column=1, columnspan=2, sticky="w", pady=6)
    btn_update.grid(row=row, column=3)
    btn_del.grid(row=row, column=4)
    row += 1
    btn_in.grid(row=row, column=1, columnspan=2, sticky="w")
    btn_out.grid(row=row, column=3)
    btn_clear.grid(row=row, column=4)
    row += 1

    # Botones de exportación
    frm_export = tk.Frame(root)
    frm_export.grid(row=row, column=0, columnspan=7, pady=10, sticky="w")
    row += 1
    
    tk.Label(frm_export, text="Exportar:").pack(side="left", padx=4)

    if rights.get("export"):
        tk.Button(frm_export, text="📄 Reg PDF", command=exp_reg_pdf).pack(side="left", padx=4)
        tk.Button(frm_export, text="📊 Reg XLS", command=exp_reg_xls).pack(side="left", padx=4)

    if rights.get("viewlog"):
        tk.Button(frm_export, text="📝 Bitácora", command=ver_log).pack(side="left", padx=4)
        tk.Button(frm_export, text="📄 Bit PDF", command=exp_log_pdf).pack(side="left", padx=4)
        tk.Button(frm_export, text="📊 Bit XLS", command=exp_log_xls).pack(side="left", padx=4)

    # Botón especial para exportar asistencia
    tk.Button(
        frm_export, text="📤 Exportar Asistencia",
        command=exportar_entradas_salidas, bg="#FF5722", fg="white"
    ).pack(side="left", padx=4)

    # Frame resumen
    frm_resumen = tk.Frame(root)
    frm_resumen.grid(row=row, column=0, columnspan=7, pady=6, sticky="w")
    row += 1

    lbl_resumen = tk.Label(
        frm_resumen,
        text="Listo",
        font=("Segoe UI", 9, "italic")
    )
    lbl_resumen.pack()

    # Hacer accesible la función desde root
    setattr(root, "actualizar_resumen", actualizar_resumen)
    actualizar_resumen("Sistema listo")

    # Configuración inicial según perfil
    if perfil in ("Super Usuario", "Admin Tipo Super Usuario"):
        on_sede_selected()

# ──────────────── INICIO APP ────────────────────────────────
def main() -> None:
    """Función principal de la aplicación."""
    global root
    
    root = tk.Tk()
    root.withdraw()
    ensure_default_account()
    root.after(100, show_login)
    root.mainloop()
    logging.info("Aplicación cerrada")

if __name__ == "__main__":
    main()
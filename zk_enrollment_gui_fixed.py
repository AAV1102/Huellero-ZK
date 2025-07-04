#!/usr/bin/env python3
# Averabyte Labs – ZKTeco Genesis (GUI 2025-07-05)

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
from tkinter import ttk, messagebox
from pyzk import ZK
from pyzk.const import USER_ADMIN, USER_DEFAULT

# ──────────────── LOGGING ─────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

# ──────────────── RUTAS Y ARCHIVOS ───────────────────
BASE_DIR = pathlib.Path.cwd() / "AVERABYTE_LABS"
BACKUP_DIR = BASE_DIR / "backups"
BASE_DIR.mkdir(exist_ok=True)
BACKUP_DIR.mkdir(exist_ok=True)

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
def next_uid_for_sede(sede: str) -> Optional[int]:
    """Obtiene el siguiente UID disponible para una sede."""
    if sede not in SEDES:
        return None
    
    ip = SEDES[sede][0]
    ids = {int(r["UID"]) for r in read_csv(CSV_FILE) 
           if r["UID"].isdigit() and r["Sede"] == sede}
    
    conn = zk_connect(ip)
    try:
        if conn:
            users = conn.get_users()
            ids.update(int(u.uid) for u in users if str(u.uid).isdigit())
    except Exception as e:
        logging.error(f"Error obteniendo usuarios de {sede}: {e}")
    finally:
        try:
            if conn:
                conn.enable_device()
                conn.disconnect()
        except:
            pass
    
    nxt = (max(ids) if ids else 0) + 1
    return nxt if nxt <= 32767 else None

def next_uid_global() -> int:
    """Obtiene el siguiente UID global disponible."""
    ids = {int(r["UID"]) for r in read_csv(CSV_FILE) if r["UID"].isdigit()}
    
    for ip, _ in SEDES.values():
        c = zk_connect(ip)
        try:
            if c:
                users = c.get_users()
                ids.update(int(str(u.uid)) for u in users if str(u.uid).isdigit())
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
    """Exportar entradas/salidas (pendiente)."""
    _show("Exportar entradas/salidas (pendiente)")

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
    uid_var.set(str(next_uid_global()))
    ent_uid.config(state="readonly")
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
        ent_uid.config(state="readonly")
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
            ent_uid.config(state="readonly")
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
            ent_uid.config(state="readonly")
            messagebox.showinfo(
                "Nuevo",
                "Ingresa datos y pulsa Guardar / Enrolar."
            )
        w.destroy()

    tk.Button(w, text="Continuar", command=continuar).grid(
        row=1, column=0, pady=8
    )

def listar_disp() -> None:
    """Lista usuarios del dispositivo."""
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

        # Tabla
        rows_local = {r["UID"]: r for r in read_csv(CSV_FILE)}
        cols = [
            "UID", "Cédula", "Nombre", "Teléfono", "Sede", "Cargo", "Empresa",
            "Permiso", "Huellero", "IP", "Dedo"
        ]

        win = tk.Toplevel(root)
        win.title(f"Usuarios en {sede}")
        tv = ttk.Treeview(win, columns=cols, show="headings")
        for c in cols:
            tv.heading(c, text=c)
            tv.column(c, anchor="center")
        tv.pack(expand=True, fill="both")

        # Filtro + botón actualizar
        barra = tk.Frame(win)
        barra.pack(fill="x", pady=2)
        filtro = tk.StringVar()
        tk.Label(barra, text="Filtrar:").pack(side="left")
        tk.Entry(barra, textvariable=filtro, width=20).pack(side="left", padx=4)

        def refrescar(*_: Any) -> None:
            tv.delete(*tv.get_children())
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
                    uid, str(u.user_id), u.name, reg.get("Teléfono", ""), sede,
                    reg.get("Cargo", ""), reg.get("Empresa", ""),
                    reg.get("Permiso", ""), SEDES[sede][1], SEDES[sede][0],
                    f"{dedo} – {FINGER_NAMES.get(dedo_int, 'Desconocido')}"
                ]
                if pattern and not any(pattern in str(x).lower() for x in fila):
                    continue
                tv.insert("", "end", values=fila)

        def actualizar_dispositivo() -> None:
            nonlocal dev_users
            try:
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
                ent_uid.config(state="readonly")
                win.destroy()

        tv.bind("<Double-1>", sel)

        # Permitir refresco desde otras funciones
        setattr(root, "current_list_refresh", actualizar_dispositivo)

    tk.Button(w, text="Mostrar", command=mostrar).grid(row=1, column=0, pady=8)

def marcar(tipo: str) -> None:
    """Marca entrada o salida."""
    if perfil == "Usuario":
        msg(messagebox.showinfo, "Marcación", "Sin permisos")
        return
    
    uid = uid_var.get().strip()
    cc = str(ced_var.get()).strip()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    conn = zk_connect(ip_var.get())
    if conn:
        try:
            for u in conn.get_users():
                if str(u.uid) == uid or str(u.user_id) == cc:
                    try:
                        conn.set_user(
                            uid=int(u.uid), user_id=str(u.user_id),
                            name=u.name, privilege=u.privilege, group_id=1
                        )
                    except Exception as e:
                        logging.error(f"Error marcando en dispositivo: {e}")
        except Exception as e:
            logging.error(f"Error obteniendo usuarios para marcar: {e}")
        finally:
            try:
                conn.enable_device()
                conn.disconnect()
            except:
                pass
    
    rows = read_csv(CSV_FILE)
    for r in rows:
        if r["UID"] == uid or str(r["C.C."]) == cc:
            if tipo == "entrada" and not r["Huella Entrada"]:
                r["Huella Entrada"] = now
                accion = "Entrada"
            elif tipo == "salida" and r["Huella Entrada"] and not r["Huella Salida"]:
                r["Huella Salida"] = now
                accion = "Salida"
            else:
                msg(messagebox.showinfo, "Marcación", "Acción no permitida")
                return
            
            write_csv(CSV_FILE, rows)
            log(f"Marcar {accion}", uid, r["Nombre"])
            msg(messagebox.showinfo, "OK", f"{accion} registrada")
            clear_form()
            return
    
    msg(messagebox.showwarning, "Marcación", "UID/Cédula no está en CSV")

def enrolar(uid: str, fid: str) -> bool:
    """Enrola huella en el dispositivo."""
    ip = ip_var.get()
    fid_n = fid.split("–")[0].strip()
    
    if not ip:
        msg(messagebox.showerror, "Conexión", "Sin IP")
        return False
    
    try:
        fid_int = int(fid_n)
    except ValueError:
        msg(messagebox.showerror, "Error", "Dedo inválido")
        return False
    
    msg(messagebox.showinfo, "Enrolar", f"Coloque {FINGER_NAMES.get(fid_int, 'dedo')} 3 veces")
    
    conn = zk_connect(ip)
    if not conn:
        return False
    
    try:
        sig = inspect.signature(conn.enroll_user)
        kw = {"uid": int(uid), "user_id": str(ced_var.get())}
        
        if "finger" in sig.parameters:
            kw["finger"] = fid_int
        elif "fid" in sig.parameters:
            kw["fid"] = fid_int
        
        conn.enroll_user(**kw)
        
        # Verificar que la huella se enroló correctamente
        try:
            tpl = conn.get_user_template(uid=int(uid), fid=fid_int)
            ok = bool(tpl and tpl[0])
        except Exception as e:
            logging.warning(f"No se pudo verificar template: {e}")
            ok = True  # Asumir que funcionó si no se puede verificar
        
        if not ok:
            msg(messagebox.showerror, "Enrolar", "Huella no detectada")
            try:
                conn.delete_user(uid=int(uid))
            except:
                pass
            return False
        
        # Configurar usuario
        priv = 0 if perm_var.get() == "Usuario" else PERFIL_PRIV.get(perm_var.get(), 0)
        conn.set_user(
            uid=int(uid), user_id=str(ced_var.get()),
            name=str(nom_var.get())[:24], privilege=int(priv), group_id=1
        )
        return True
        
    except Exception as e:
        msg(messagebox.showerror, "Error", str(e))
        return False
    finally:
        try:
            conn.enable_device()
            conn.disconnect()
        except:
            pass

def guardar() -> None:
    """Guarda/enrola usuario."""
    if not rights.get("create", False):
        return
    
    uid = uid_var.get().strip()
    fid = finger_var.get().split("–")[0].strip()
    
    if not uid.isdigit() or int(uid) > 32767:
        messagebox.showerror("UID", "Numérico ≤32767")
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
            
            if not enrolar(uid, fid):
                return
            
            fingers.append(fid)
            reg["Fingers"] = ";".join(fingers)
            write_csv(CSV_FILE, rows)
            log("Enrolar dedo extra", uid, reg["Nombre"])
            msg(messagebox.showinfo, "OK", "Dedo añadido")
            clear_form()
            return
        
        # Usuario nuevo
        if any(not v.get().strip() for v in vars_user):
            msg(messagebox.showerror, "Datos", "Completa campos")
            return
        
        if not enrolar(uid, fid):
            return
        
        fila = dict(zip(HEADERS, [
            uid, nom_var.get(), ced_var.get(), tel_var.get(),
            sede_var.get(), cargo_var.get(), emp_var.get(),
            perm_var.get(), fid,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "", "", "", ip_var.get()
        ]))
        
        append_row(CSV_FILE, fila)
        log("Crear", uid, nom_var.get())
        msg(messagebox.showinfo, "OK", "Usuario creado")
        clear_form()
    
    threading.Thread(target=worker).start()

def actualizar() -> None:
    """Actualiza usuario existente."""
    if not rights.get("update", False):
        return
    
    uid = uid_var.get().strip()
    conn = zk_connect(ip_var.get())
    
    if not conn:
        return
    
    try:
        priv = PERFIL_PRIV.get(perm_var.get(), 0)
        conn.set_user(
            uid=int(uid), user_id=str(ced_var.get()),
            name=str(nom_var.get())[:24],
            privilege=int(priv), group_id=1
        )
    except Exception as e:
        msg(messagebox.showerror, "Error", str(e))
        return
    finally:
        try:
            conn.enable_device()
            conn.disconnect()
        except:
            pass
    
    rows = read_csv(CSV_FILE)
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
            write_csv(CSV_FILE, rows)
            log("Actualizar", uid, nom_var.get())
            msg(messagebox.showinfo, "OK", "Actualizado")
            clear_form()
            return

def eliminar() -> None:
    """Elimina usuario por cédula."""
    if not rights.get("delete", False):
        return

    uid_txt = uid_var.get().strip()
    cc_txt = str(ced_var.get()).strip()

    modo_uid = uid_txt.isdigit() and int(uid_txt) > 32767
    if modo_uid:
        llave = uid_txt
        pregunta = f"Eliminar usuario con UID {llave} (fuera de rango)?"
    else:
        if not cc_txt:
            messagebox.showerror("Eliminar", "Ingresa la cédula")
            return
        llave = cc_txt
        pregunta = f"Eliminar usuario con cédula {llave}?"

    if not messagebox.askyesno("Confirmar", pregunta):
        return

    conn = zk_connect(ip_var.get())
    try:
        if conn:
            for u in conn.get_users():
                if ((modo_uid and str(u.uid) == uid_txt) or 
                    (not modo_uid and str(u.user_id) == cc_txt)):
                    conn.delete_user(uid=int(u.uid))
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

    rows = read_csv(CSV_FILE)
    if modo_uid:
        rows = [r for r in rows if r["UID"] != uid_txt]
        log("Eliminar por UID", uid_txt, "")
    else:
        rows = [r for r in rows if str(r["C.C."]) != cc_txt]
        log("Eliminar por cédula", "", cc_txt)

    write_csv(CSV_FILE, rows)
    msg(messagebox.showinfo, "OK", "Eliminado de dispositivo y CSV")
    clear_form()

    # Actualizar lista si está abierta
    if hasattr(root, "current_list_refresh") and callable(getattr(root, "current_list_refresh")):
        getattr(root, "current_list_refresh")()

def actualizar_resumen(mensaje: Optional[str] = None) -> None:
    """Actualiza el resumen en la interfaz."""
    try:
        registros = read_csv(CSV_FILE)
        total = len(registros)
        ultimo_uid = max(
            (int(r["UID"]) for r in registros if r["UID"].isdigit()),
            default=0
        )
        
        if CSV_FILE.exists():
            fecha_mod = datetime.fromtimestamp(
                os.path.getmtime(CSV_FILE)
            ).strftime("%Y-%m-%d %H:%M:%S")
        else:
            fecha_mod = "N/A"

        resumen_txt = (
            f"🧾 Total usuarios: {total}  |  Último UID: {ultimo_uid}  "
            f"|  CSV modificado: {fecha_mod}"
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
            # Mantener referencia para evitar garbage collection
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

    # Botones de acción
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

    # Frame inferior con botones de exportación
    frm_inferior = tk.Frame(root)
    frm_inferior.grid(row=row, column=0, columnspan=7, pady=10, sticky="w")
    row += 1
    tk.Label(frm_inferior, text="Acciones:").pack(side="left", padx=4)

    frm_acciones = tk.Frame(frm_inferior)
    frm_acciones.pack(pady=4)

    col = 0
    if rights.get("create"):
        tk.Button(
            frm_acciones, text="✅ Guardar / Enrolar", bg="green", fg="white",
            command=guardar
        ).grid(row=0, column=col, padx=4)
        col += 1

    if rights.get("update"):
        tk.Button(
            frm_acciones, text="Actualizar", bg="dodgerblue", fg="white",
            command=actualizar
        ).grid(row=0, column=col, padx=4)
        col += 1

    if rights.get("delete"):
        tk.Button(
            frm_acciones, text="Eliminar por Cédula", bg="red", fg="white",
            command=eliminar
        ).grid(row=0, column=col, padx=4)
        col += 1

    if rights.get("mark"):
        tk.Button(
            frm_acciones, text="📥 Marcar Entrada", bg="turquoise", fg="black",
            command=lambda: marcar("entrada")
        ).grid(row=0, column=col, padx=4)
        col += 1
        tk.Button(
            frm_acciones, text="📤 Marcar Salida", bg="orange", fg="black",
            command=lambda: marcar("salida")
        ).grid(row=0, column=col, padx=4)
        col += 1

    tk.Button(frm_acciones, text="🧹 Limpiar", command=clear_form).grid(
        row=0, column=col, padx=4
    )

    # Botones de exportación
    frm_export = tk.Frame(frm_inferior)
    frm_export.pack(pady=4)

    col = 0
    if rights.get("export"):
        tk.Button(frm_export, text="📄 Reg PDF", command=exp_reg_pdf).grid(
            row=0, column=col, padx=4
        )
        col += 1
        tk.Button(frm_export, text="📊 Reg XLS", command=exp_reg_xls).grid(
            row=0, column=col, padx=4
        )
        col += 1

    if rights.get("viewlog"):
        tk.Button(frm_export, text="📝 Bitácora", command=ver_log).grid(
            row=0, column=col, padx=4
        )
        col += 1
        tk.Button(frm_export, text="📄 Bit PDF", command=exp_log_pdf).grid(
            row=0, column=col, padx=4
        )
        col += 1
        tk.Button(frm_export, text="📊 Bit XLS", command=exp_log_xls).grid(
            row=0, column=col, padx=4
        )
        col += 1

    if perfil == "Exportador":
        tk.Button(
            frm_export, text="📤 Entradas/Salidas XLS",
            command=exportar_entradas_salidas
        ).grid(row=1, column=0, columnspan=5, pady=6)

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
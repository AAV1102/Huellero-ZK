#!/usr/bin/env python3
# Averabyte Labs – ZKTeco Genesis Investments  (GUI 2025-07-05)

import os, csv, shutil, pathlib, hashlib, inspect, atexit, threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from pyzk import ZK, const
import pandas as pd
from fpdf import FPDF

# ───────────────── rutas / carpetas ─────────────────────────────
BASE_DIR   = pathlib.Path.cwd() / "AVERABYTE_LABS"
BACKUP_DIR = BASE_DIR / "backups"
BASE_DIR.mkdir(exist_ok=True)
BACKUP_DIR.mkdir(exist_ok=True)

CSV_FILE      = BASE_DIR / "registro_usuarios.csv"
BITACORA      = BASE_DIR / "bitacora_acciones.csv"
ACCOUNTS_FILE = BASE_DIR / "accounts.csv"
LOGO_PATH     = BASE_DIR / "logo_averabyte_labs.png"
ICON_PATH     = BASE_DIR / "icon_averabyte_labs.png"

EXPORT_REG_PDF = BASE_DIR / "reg_usuarios.pdf"
EXPORT_REG_XLS = BASE_DIR / "reg_usuarios.xlsx"
EXPORT_LOG_PDF = BASE_DIR / "bitacora.pdf"
EXPORT_LOG_XLS = BASE_DIR / "bitacora.xlsx"

# ──────────────── SEDES Y HUELLEROS ──────────────────────────
SEDES = {
    "MEDELLIN":      ("192.168.160.200", "K40/ID"),
    "AUTOFAX":       ("192.168.162.200", "K40/ID"),
    "FONTIBON":      ("192.168.163.200", "K40/ID"),
    "BARRANQUILLA":  ("192.168.164.200", "K40/ID"),
    "BOGOTASUR":     ("192.168.165.200", "K40/ID"),
    "VILLAVICENCIO": ("192.168.166.200", "K40/ID"),
    "ZIPAQUIRA":     ("192.168.167.200", "K40/ID"),
    "PEREIRA":       ("192.168.168.200", "K40/ID"),
    "DUITAMA":       ("192.168.182.200", "K40/ID"),
    "CALI":          ("192.168.170.200", "K40/ID"),
    "NEIVA":         ("192.168.171.200", "K40/ID"),
    "IBAGUE":        ("192.168.172.200", "K40/ID"),
    "BUCARAMANGA":   ("192.168.173.200", "K40/ID"),
    "CARTAGENA":     ("192.168.174.200", "K40/ID"),
    "MONTERIA":      ("192.168.175.200", "UA300/ID"),
    "SISTEMA_V":     ("192.168.176.200", "K40/ID"),
    "MOSQUERA":      ("192.168.177.200", "K40/ID"),
    "CAYENA":        ("192.168.178.200", "UA300/ID"),
    "20":            ("192.168.180.200", "K40/ID"),
    "HATILLO":       ("192.168.160.200", "K40/ID"),
    "COOWORKING":    ("192.168.199.246", "UA300/ID"),
}

# ──────────────── constantes proyecto ──────────────────────────
HEADERS = [
    "UID","Nombre","C.C.","Teléfono","Sede","Cargo","Empresa",
    "Permiso","Fingers","Fecha Creación","Fecha Modificación",
    "Huella Entrada","Huella Salida","IP"
]

PERFILES = [
    "Super Usuario",
    "Admin Tipo Super Usuario",
    "Admin por Sede",
    "Exportador",
    "Usuario"
]

PERFIL_PRIV = {
    "Super Usuario":            const.USER_ADMIN,
    "Admin Tipo Super Usuario": const.USER_ADMIN,
    "Admin por Sede":           const.USER_ADMIN,
    "Exportador":               const.USER_DEFAULT,
    "Usuario":                  const.USER_DEFAULT,
}

PERM_RIGHTS = {
    "Super Usuario":            dict(create=True, update=True, delete=True,
                                     mark=True, export=True, lista=True),
    "Admin Tipo Super Usuario": dict(create=True, update=True, delete=True,
                                     mark=True, export=True, lista=True),
    "Admin por Sede":           dict(create=False, update=True, delete=False,
                                     mark=True, export=True, lista=True),
    "Exportador":               dict(create=False, update=False, delete=False,
                                     mark=False, export=True, lista=False),
    "Usuario":                  dict(create=False, update=False, delete=False,
                                     mark=False, export=False, lista=False),
}

FINGER_NAMES = {
    0:"Pulgar D",1:"Índice D",2:"Medio D",3:"Anular D",4:"Meñique D",
    5:"Pulgar I",6:"Índice I",7:"Medio I",8:"Anular I",9:"Meñique I"
}
FINGER_OPTIONS = [f"{i} – {FINGER_NAMES[i]}" for i in range(10)]

# ──────────────── CSV / bitácora / backup ──────────────────────
def sha(txt) -> str:
    return hashlib.sha256(str(txt).encode()).hexdigest()
def read_csv(p):                 return [] if not p.exists() else list(csv.DictReader(p.open()))
def write_csv(p, rows):
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HEADERS); w.writeheader(); w.writerows(rows)
    backup_csv()
def append_row(p, row):
    new = not p.exists()
    with p.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HEADERS)
        if new: w.writeheader()
        w.writerow(row)
    backup_csv()
def log(act, uid, name, det=""):
    new = not BITACORA.exists()
    with BITACORA.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new: w.writerow(["Fecha","Acción","UID","Nombre","Detalle"])
        w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    act, uid, name, det])
    backup_csv()
def backup_csv():
    stamp = datetime.now().strftime("%Y%m%d")
    for src in (CSV_FILE, BITACORA):
        if src.exists():
            dst = BACKUP_DIR / f"{src.stem}_{stamp}.csv"
            if not dst.exists():
                shutil.copy2(src, dst)
atexit.register(backup_csv)

# ──────────────── cuentas login ────────────────────────────────
def ensure_default_account():
    if ACCOUNTS_FILE.exists():
        return
    with ACCOUNTS_FILE.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["Usuario","Hash","Perfil"])
        w.writerow(["admin", sha("admin123"), "Super Usuario"])
def check_login(user, pwd):
    rows = list(csv.DictReader(ACCOUNTS_FILE.open()))
    for r in rows:
        if r["Usuario"] == user and r["Hash"] == sha(pwd):
            return r["Perfil"]
    return None

# ──────────────── dispositivo (pyzk) ───────────────────────────
def zk_connect(ip=None):
    if not ip:
        ip = "192.168.199.246"
    try:
        zk  = ZK(ip, port=4370, password=0, ommit_ping=True)
        conn = zk.connect(); conn.disable_device(); return conn
    except Exception as e:
        messagebox.showerror("Conexión", e)

def next_uid_global():
    ids = {int(r["UID"]) for r in read_csv(CSV_FILE) if r["UID"].isdigit()}
    conn = zk_connect()
    if conn:
        try:
            ids.update(int(u.uid) for u in conn.get_users() if str(u.uid).isdigit())
        finally:
            conn.enable_device(); conn.disconnect()
    next_uid = max(ids)+1 if ids else 1001
    return next_uid if next_uid <= 32767 else 1001

# ──────────────── Exportar funciones vacías (puedes implementar luego) ──────────
def exp_reg_pdf():
    messagebox.showinfo("Exportar", "Función de exportar a PDF no implementada.")

def exp_reg_xls():
    messagebox.showinfo("Exportar", "Función de exportar a Excel no implementada.")

def exp_log_pdf():
    messagebox.showinfo("Exportar", "Función de exportar bitácora a PDF no implementada.")

def exp_log_xls():
    messagebox.showinfo("Exportar", "Función de exportar bitácora a Excel no implementada.")

def ver_log():
    messagebox.showinfo("Bitácora", "Función de ver bitácora no implementada.")

def exportar_entradas_salidas():
    messagebox.showinfo("Exportar", "Función de exportar entradas/salidas no implementada.")

# ──────────────── Login GUI ───────────────────────────────────
def show_login():
    dlg = tk.Toplevel()
    dlg.title("Login – Averabyte Labs")
    dlg.resizable(False, False)
    dlg.grab_set()
    dlg.protocol("WM_DELETE_WINDOW", root.destroy)

    tk.Label(dlg, text="Usuario").grid(row=0, column=0, padx=6, pady=4)
    tk.Label(dlg, text="Contraseña").grid(row=1, column=0)

    user = tk.StringVar()
    pwd  = tk.StringVar()

    tk.Entry(dlg, textvariable=user).grid(row=0, column=1)
    tk.Entry(dlg, textvariable=pwd, show="*").grid(row=1, column=1)

    def try_login():
        perfil = check_login(user.get(), pwd.get())
        if not perfil:
            messagebox.showerror("Login", "Credenciales inválidas"); return
        dlg.destroy()
        build_main_gui(perfil)

    tk.Button(dlg, text="Ingresar", command=try_login) \
        .grid(row=2, column=0, columnspan=2, pady=6)
    

# ──────────────── GUI principal (según perfil) ────────────────
def build_main_gui(perfil):
    rights = PERM_RIGHTS[perfil]

    def show_msgbox(func, *args, **kwargs):
        root.after(0, lambda: func(*args, **kwargs))

    # --- helpers para sede y huellero ---
    def on_sede_selected(event=None):
        sede = sede_var.get()
        if sede in SEDES:
            huellero_var.set(SEDES[sede][1])
            ip_var.set(SEDES[sede][0])
        else:
            huellero_var.set("")
            ip_var.set("")

    def on_finger_sel(*_):
        val = finger_var.get()
        if "–" in val:
            lbl_dedo.config(text=val)
        else:
            try:
                idx = int(val)
                lbl_dedo.config(text=FINGER_OPTIONS[idx])
            except:
                lbl_dedo.config(text="")

    def clear_form():
        for v in vars_user + [perm_var, finger_var, huellero_var, ip_var]:
            v.set("")
        finger_var.set(FINGER_OPTIONS[0])
        on_finger_sel()
        ent_uid.config(state="normal")

    def nuevo():
        clear_form()
        uid_var.set(str(next_uid_global()))
        ent_uid.config(state="readonly")
        if perfil in ("Super Usuario", "Admin Tipo Super Usuario"):
            on_sede_selected()
        if rights["create"]:
            btn_save.config(state="normal")

    # --- buscar por UID, C.C., Sede, Huellero o IP ---
    def buscar():
        q = search_var.get().strip().lower()
        if not q:
            return

        rows = read_csv(CSV_FILE)
        reg = next(
            (
                r for r in rows
                if q in str(r.get("UID", "")).lower()
                or q in str(r.get("C.C.", "")).lower()
                or q in str(r.get("Sede", "")).lower()
                or q in str(r.get("Huellero", "")).lower()
                or q in str(r.get("IP", "")).lower()
            ),
            None
        )

        if reg:
            uid_var.set(reg.get("UID", ""))
            nom_var.set(reg.get("Nombre", ""))
            ced_var.set(str(reg.get("C.C.", "")))
            tel_var.set(str(reg.get("Teléfono", "")))
            sede_var.set(reg.get("Sede", ""))
            cargo_var.set(reg.get("Cargo", ""))
            emp_var.set(reg.get("Empresa", ""))
            perm_var.set(reg.get("Permiso", ""))
            huellero_var.set(reg.get("Huellero", SEDES.get(reg.get("Sede",""), ["",""])[1]))
            ip_var.set(reg.get("IP", SEDES.get(reg.get("Sede",""), ["",""])[0]))
            fingers = reg.get("Fingers", "")
            if fingers:
                dedo_num = fingers.split(";")[0]
                finger_var.set(f"{dedo_num} – {FINGER_NAMES.get(int(dedo_num),'')}")
                on_finger_sel()
            else:
                finger_var.set(FINGER_OPTIONS[0])
                on_finger_sel()
            toggle_perm()
            return

        # Si no está en CSV, pregunta sede para buscar en dispositivo
        def buscar_en_disp():
            sede_win = tk.Toplevel(root)
            sede_win.title("Selecciona la sede para buscar en el dispositivo")
            tk.Label(sede_win, text="Sede:").grid(row=0, column=0, padx=8, pady=8)
            sede_sel = tk.StringVar()
            cb = ttk.Combobox(sede_win, textvariable=sede_sel, values=sorted(SEDES.keys()), state="readonly", width=30)
            cb.grid(row=0, column=1, padx=8, pady=8)
            cb.focus_set()

            def buscar_disp_final():
                sede = sede_sel.get()
                if not sede:
                    messagebox.showwarning("Sede", "Debes seleccionar una sede.")
                    return
                ip = SEDES[sede][0]
                conn = zk_connect(ip)
                if conn:
                    try:
                        dev_users = conn.get_users()
                        found = None
                        for u in dev_users:
                            if (
                                q in str(u.uid).lower()
                                or q in str(u.user_id).lower()
                                or q in str(u.name).lower()
                            ):
                                found = u
                                break
                        if found:
                            uid_var.set(str(found.uid))
                            nom_var.set(found.name)
                            ced_var.set(str(found.user_id))
                            sede_var.set(sede)
                            huellero_var.set(SEDES[sede][1])
                            ip_var.set(ip)
                            ent_uid.config(state="readonly")
                            messagebox.showinfo("Solo en dispositivo",
                                "El usuario existe en el dispositivo pero no en el CSV local.\n"
                                "Puedes completar los datos y guardar para sincronizar.")
                        else:
                            clear_form()
                            ced_var.set(q)
                            perm_var.set("Usuario")
                            uid_var.set(str(next_uid_global()))
                            sede_var.set(sede)
                            huellero_var.set(SEDES[sede][1])
                            ip_var.set(ip)
                            ent_uid.config(state="readonly")
                            messagebox.showinfo("Nuevo",
                                "No existe en dispositivo. Ingresa datos y pulsa Guardar / Enrolar.")
                    except Exception as e:
                        messagebox.showerror("Error", str(e))
                    finally:
                        conn.enable_device(); conn.disconnect()
                sede_win.destroy()

            tk.Button(sede_win, text="Buscar", command=buscar_disp_final).grid(row=1, column=0, columnspan=2, pady=8)

        buscar_en_disp()

    # --- Enlistar con filtro por sede, huellero o IP y todos los campos ---
    def listar_disp():
        if not rights["lista"]:
            return

        sede_sel = tk.StringVar(value="")
        win_sel = tk.Toplevel(root)
        win_sel.title("Selecciona la sede")
        tk.Label(win_sel, text="Sede:").grid(row=0, column=0, padx=8, pady=8)
        cb = ttk.Combobox(win_sel, textvariable=sede_sel, values=sorted(SEDES.keys()), state="readonly", width=30)
        cb.grid(row=0, column=1, padx=8, pady=8)
        cb.focus_set()

        def mostrar_usuarios():
            sede = sede_sel.get()
            if not sede:
                show_msgbox(messagebox.showwarning, "Sede", "Debes seleccionar una sede.")
                return
            ip = SEDES[sede][0]
            # Verificar si el dispositivo está en línea
            try:
                conn = zk_connect(ip)
                if not conn:
                    raise Exception("No se pudo conectar al dispositivo.")
            except Exception as e:
                show_msgbox(messagebox.showerror, "Conexión", f"No se pudo conectar a la sede '{sede}' ({ip}):\n{e}")
                return
            finally:
                try:
                    conn.enable_device(); conn.disconnect()
                except:
                    pass
            win_sel.destroy()

            # Si está en línea, obtener usuarios
            try:
                conn = zk_connect(ip)
                dev_users = conn.get_users()
            except Exception as e:
                show_msgbox(messagebox.showerror, "Error", str(e))
                return
            finally:
                if conn:
                    conn.enable_device(); conn.disconnect()

            rows_local = {r["UID"]: r for r in read_csv(CSV_FILE)}

            cols = [
                "UID", "Cédula", "Nombre", "Teléfono", "Sede", "Cargo", "Empresa",
                "Permiso", "Huellero", "IP", "Dedo"
            ]

            win = tk.Toplevel(root)
            win.title(f"Usuarios en {sede}")

            tv = ttk.Treeview(win, columns=cols, show="headings")
            for c in cols:
                tv.heading(c, text=c); tv.column(c, anchor="center")
            tv.pack(expand=True, fill="both")

            filtro_var = tk.StringVar()
            tk.Label(win, text="Filtrar:").pack(side="left", padx=4)
            tk.Entry(win, textvariable=filtro_var, width=20).pack(side="left", padx=4)

            def refrescar_lista(*_):
                filtro = filtro_var.get().strip().lower()
                tv.delete(*tv.get_children())
                for u in dev_users:
                    uid = str(u.uid)
                    reg = rows_local.get(uid, {})
                    nombre = u.name
                    cedula = str(u.user_id)
                    telefono = str(reg.get("Teléfono", ""))
                    cargo = reg.get("Cargo", "")
                    empresa = reg.get("Empresa", "")
                    permiso = reg.get("Permiso", "")
                    huellero = SEDES.get(sede, ("", ""))[1]
                    ip_disp = SEDES.get(sede, ("", ""))[0]
                    fingers = reg.get("Fingers", "")
                    if fingers:
                        dedo_num = fingers.split(";")[0]
                    else:
                        dedo_num = "0"
                    dedo_txt = f"{dedo_num} – {FINGER_NAMES.get(int(dedo_num), '')}"

                    valores = [
                        uid, cedula, nombre, telefono, sede, cargo, empresa, permiso, huellero, ip_disp, dedo_txt
                    ]
                    if filtro and not any(filtro in str(v).lower() for v in valores):
                        continue

                    tv.insert("", "end", values=valores)

            filtro_var.trace_add("write", lambda *_: refrescar_lista())
            refrescar_lista()

            def on_sel(e):
                item = tv.focus()
                if item:
                    vals = tv.item(item, "values")
                    uid_var.set(vals[0])
                    ced_var.set(str(vals[1]))
                    nom_var.set(vals[2])
                    tel_var.set(str(vals[3]))
                    sede_var.set(vals[4])
                    cargo_var.set(vals[5])
                    emp_var.set(vals[6])
                    perm_var.set(vals[7])
                    huellero_var.set(vals[8])
                    ip_var.set(vals[9])
                    dedo_val = vals[10].split("–")[0].strip() if len(vals) > 10 else "0"
                    dedo_combo_val = f"{dedo_val} – {FINGER_NAMES.get(int(dedo_val), '')}"
                    finger_var.set(dedo_combo_val)
                    on_finger_sel()
                    ent_uid.config(state="readonly")
                    win.destroy()
            tv.bind("<Double-1>", on_sel)

        tk.Button(win_sel, text="Mostrar usuarios", command=mostrar_usuarios).grid(row=1, column=0, columnspan=2, pady=8)

    def toggle_perm():
        pass

    def marcar(tipo):
        if perfil == "Usuario":
            show_msgbox(messagebox.showinfo, "Marcación", "No tienes permisos para marcar entrada/salida desde aquí.")
            return
        uid = uid_var.get().strip()
        user_id = str(ced_var.get()).strip()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Marcar en dispositivo
        marcado = False
        conn = zk_connect(ip_var.get())
        if conn:
            try:
                users = conn.get_users()
                for u in users:
                    if (str(u.uid) == uid or str(u.user_id) == user_id):
                        try:
                            if tipo == "entrada":
                                conn.set_user(uid=int(u.uid), user_id=str(u.user_id), name=u.name, privilege=u.privilege, group_id=1)
                            elif tipo == "salida":
                                conn.set_user(uid=int(u.uid), user_id=str(u.user_id), name=u.name, privilege=u.privilege, group_id=1)
                            marcado = True
                        except Exception:
                            pass
            finally:
                conn.enable_device(); conn.disconnect()
        # Marcar en CSV
        rows = read_csv(CSV_FILE)
        for r in rows:
            if r["UID"] == uid or str(r["C.C."]) == user_id:
                if tipo == "entrada" and not r["Huella Entrada"]:
                    r["Huella Entrada"] = now
                    accion = "Entrada"
                elif tipo == "salida" and r["Huella Entrada"] and not r["Huella Salida"]:
                    r["Huella Salida"] = now
                    accion = "Salida"
                else:
                    show_msgbox(messagebox.showinfo, "Marcación", "Acción no permitida.")
                    return
                write_csv(CSV_FILE, rows)
                log(f"Marcar {accion}", uid, r["Nombre"])
                show_msgbox(messagebox.showinfo, "OK", f"{accion} registrada en dispositivo y CSV.")
                show_msgbox(clear_form)
                return
        show_msgbox(messagebox.showwarning, "Marcación", "UID/Cédula no está en CSV.")

    def enrolar(uid, fid):
        ip = ip_var.get()
        def show_msgbox_local(func, *args, **kwargs):
            root.after(0, lambda: func(*args, **kwargs))

        if not ip:
            show_msgbox_local(messagebox.showerror, "Conexión", "No hay IP de sede seleccionada.")
            return False

        fid_num = fid.split("–")[0].strip() if "–" in fid else fid
        show_msgbox_local(messagebox.showinfo, "Enrolar", f"Coloque {FINGER_NAMES[int(fid_num)]} 3 veces en el equipo.")

        conn = zk_connect(ip)
        if not conn:
            return False
        try:
            sig = inspect.signature(conn.enroll_user)
            kwargs = {
                "uid": int(uid),
                "user_id": str(ced_var.get())
            }
            if "finger" in sig.parameters:
                kwargs["finger"] = int(fid_num)
            elif "fid" in sig.parameters:
                kwargs["fid"] = int(fid_num)
            conn.enroll_user(**kwargs)
            privilege = PERFIL_PRIV[perm_var.get()]
            if perm_var.get() == "Usuario":
                privilege = 0
            conn.set_user(
                uid=int(uid),
                user_id=str(ced_var.get()),
                name=str(nom_var.get())[:24],
                privilege=int(privilege),
                group_id=1
            )
            return True
        except Exception as e:
            show_msgbox_local(messagebox.showerror, "Error", str(e))
            return False
        finally:
            conn.enable_device(); conn.disconnect()

    def guardar():
        if not rights["create"]:
            return
        uid = uid_var.get().strip()
        if not uid.isdigit() or int(uid) > 32767:
            return messagebox.showerror("UID", "El UID debe ser numérico y menor o igual a 32767.")
        rows = read_csv(CSV_FILE)
        reg  = next((r for r in rows if r["UID"] == uid), None)
        fid  = finger_var.get().split("–")[0].strip()

        def do_enroll():
            if reg:
                fingers = reg["Fingers"].split(";") if reg["Fingers"] else []
                if fid in fingers:
                    show_msgbox(messagebox.showwarning, "Duplicado", "Ese dedo ya está registrado.")
                    return
                if not enrolar(uid, fid):
                    return
                fingers.append(fid)
                reg["Fingers"] = ";".join(fingers)
                write_csv(CSV_FILE, rows)
                log("Enrolar dedo extra", uid, reg["Nombre"], FINGER_NAMES[int(fid)])
                show_msgbox(messagebox.showinfo, "OK", "Dedo añadido.")
                show_msgbox(clear_form)
                return

            if any(not v.get().strip() for v in vars_user):
                show_msgbox(messagebox.showerror, "Datos", "Completa todos los campos.")
                return
            if not enrolar(uid, fid):
                return
            fila = dict(zip(HEADERS, [
                uid,
                nom_var.get(),
                str(ced_var.get()),
                str(tel_var.get()),
                sede_var.get(),
                cargo_var.get(),
                emp_var.get(),
                perm_var.get(),
                fid,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "", "", "",
                ip_var.get()
            ]))
            append_row(CSV_FILE, fila)
            log("Crear", uid, nom_var.get(), perm_var.get())
            show_msgbox(messagebox.showinfo, "OK", "Usuario creado y enrolado.")
            show_msgbox(clear_form)

        threading.Thread(target=do_enroll).start()

    def actualizar():
        if not rights["update"]:
            return
        uid = uid_var.get().strip()
        rows = read_csv(CSV_FILE)
        conn = zk_connect(ip_var.get())
        if not conn:
            return
        try:
            conn.set_user(
                uid=int(uid),
                user_id=str(ced_var.get()),
                name=str(nom_var.get())[:24],
                privilege=int(PERFIL_PRIV[perm_var.get()]),
                group_id=1
            )
        except Exception as e:
            show_msgbox(messagebox.showerror, "Error", str(e))
            return
        finally:
            conn.enable_device(); conn.disconnect()

        for r in rows:
            if r["UID"] == uid:
                r.update({
                    "Nombre": nom_var.get(),
                    "C.C.":   str(ced_var.get()),
                    "Teléfono": str(tel_var.get()),
                    "Sede": sede_var.get(),
                    "Cargo": cargo_var.get(),
                    "Empresa": emp_var.get(),
                    "Permiso": perm_var.get(),
                    "Fecha Modificación": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "IP": ip_var.get()
                })
                write_csv(CSV_FILE, rows)
                log("Actualizar", uid, nom_var.get())
                show_msgbox(messagebox.showinfo, "OK", "Actualizado.")
                show_msgbox(clear_form)
                return

    # --- Eliminar por Cédula ---
    def eliminar_por_cedula():
        if not rights["delete"]:
            return
        user_id = str(ced_var.get()).strip()
        if not user_id:
            return messagebox.showerror("Cédula", "Debes ingresar la cédula.")
        if not messagebox.askyesno("Seguro", f"Eliminar usuario con cédula {user_id} del dispositivo y del CSV?"):
            return

        eliminado_dispositivo = False
        conn = zk_connect(ip_var.get())
        if conn:
            try:
                users = conn.get_users()
                for u in users:
                    if str(u.user_id) == user_id:
                        try:
                            conn.delete_user(uid=int(u.uid))
                            eliminado_dispositivo = True
                        except Exception:
                            try:
                                conn.delete_user(user_id=str(u.user_id))
                                eliminado_dispositivo = True
                            except Exception:
                                pass
                if eliminado_dispositivo:
                    show_msgbox(messagebox.showinfo, "OK", f"Usuario con cédula {user_id} eliminado del dispositivo.")
                else:
                    show_msgbox(messagebox.showwarning, "Reloj", "Usuario no encontrado en el dispositivo.")
            except Exception as e:
                show_msgbox(messagebox.showwarning, "Reloj", str(e))
            finally:
                conn.enable_device(); conn.disconnect()

        # Eliminar del CSV
        rows = read_csv(CSV_FILE)
        write_csv(CSV_FILE, [r for r in rows if str(r["C.C."]) != user_id])
        log("Eliminar por cédula", "", user_id)
        show_msgbox(messagebox.showinfo, "OK", "Eliminado del CSV y se intentó eliminar del dispositivo.")
        show_msgbox(clear_form)

    # ── construir layout (logo / icono) ─────────────────────
    root.deiconify()
    root.title(f"Averabyte Labs – ZKTeco Genesis  ({perfil})")

    if LOGO_PATH.exists():
        try:
            img_logo = tk.PhotoImage(file=str(LOGO_PATH))
            lbl_logo = tk.Label(root, image=img_logo)
            lbl_logo.image = img_logo
            lbl_logo.grid(row=0, column=0, rowspan=3, padx=4)
        except tk.TclError:
            pass

    if ICON_PATH.exists():
        try:
            root.iconphoto(False, tk.PhotoImage(file=str(ICON_PATH)))
        except tk.TclError:
            pass

    # --- Botones y barra superior ---
    btn_list   = tk.Button(root, text="📋 Lista disp.", command=listar_disp)
    btn_nuevo  = tk.Button(root, text="➕ Nuevo", bg="#8bc34a", fg="white",
                           width=10, command=nuevo)

    search_var = tk.StringVar()
    tk.Label(root, text="Buscar UID/C.C./Sede/Huellero/IP").grid(row=0, column=2, sticky="e")
    entry_search = tk.Entry(root, textvariable=search_var, width=18)
    entry_search.grid(row=0, column=3)
    btn_search = tk.Button(root, text="Buscar", command=buscar)
    btn_search.grid(row=0, column=4, padx=2)
    btn_list.grid(row=0, column=1, padx=2, pady=6)
    btn_nuevo.grid(row=0, column=6, padx=2, pady=6)

    # --- Campos del formulario ---
    labels = ["UID","Nombre","C.C.","Teléfono","Sede","Cargo","Empresa","Permiso"]
    uid_var, nom_var, ced_var, tel_var = (tk.StringVar() for _ in range(4))
    sede_var, cargo_var, emp_var       = (tk.StringVar() for _ in range(3))
    perm_var = tk.StringVar(value=PERFILES[-1])
    finger_var = tk.StringVar(value=FINGER_OPTIONS[0])
    huellero_var = tk.StringVar()
    ip_var = tk.StringVar()

    vars_user = [
        uid_var, nom_var, ced_var, tel_var,
        sede_var, cargo_var, emp_var
    ]

    row = 1
    for lbl, var in zip(labels, vars_user + [perm_var]):
        tk.Label(root, text=lbl).grid(row=row, column=1, sticky="e")
        if lbl == "Permiso":
            ttk.Combobox(
                root, textvariable=perm_var,
                values=PERFILES, state="readonly",
                width=33
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
                e = tk.Entry(root, textvariable=sede_var, state="readonly", width=35)
                e.grid(row=row, column=2, columnspan=3, padx=2, pady=1)
        else:
            e = tk.Entry(root, textvariable=var, width=35)
            e.grid(row=row, column=2, columnspan=3, padx=2, pady=1)
            if lbl == "UID":
                ent_uid = e
            if lbl == "C.C.":
                entry_cedula = e  # Este es el campo de cédula visible en el formulario
        row += 1

    tk.Label(root, text="Huellero").grid(row=row, column=1, sticky="e")
    tk.Entry(root, textvariable=huellero_var, state="readonly", width=35)\
        .grid(row=row, column=2, columnspan=3, padx=2, pady=1)
    row += 1

    tk.Label(root, text="IP").grid(row=row, column=1, sticky="e")
    tk.Entry(root, textvariable=ip_var, state="readonly", width=35)\
        .grid(row=row, column=2, columnspan=3, padx=2, pady=1)
    row += 1

    tk.Label(root, text="Dedo").grid(row=row, column=1, sticky="e")
    cb_finger = ttk.Combobox(root, textvariable=finger_var, values=FINGER_OPTIONS,
                             width=15, state="readonly")
    cb_finger.grid(row=row, column=2, sticky="w")
    lbl_dedo = tk.Label(root, text=FINGER_OPTIONS[0])
    lbl_dedo.grid(row=row, column=3, columnspan=2, sticky="w")
    finger_var.trace_add("write", on_finger_sel)
    row += 1

    btn_save   = tk.Button(root, text="💾 Guardar / Enrolar",
                           bg="#4caf50", fg="white", width=18,
                           command=guardar)
    btn_update = tk.Button(root, text="Actualizar",
                           bg="#2196f3", fg="white", width=12,
                           command=actualizar)
    btn_delete_ced = tk.Button(root, text="Eliminar por Cédula",
                               bg="#f44336", fg="white", width=18,
                               command=eliminar_por_cedula)
    btn_mark_in  = tk.Button(root, text="Marcar Entrada",
                             bg="#009688", fg="white", width=14,
                             command=lambda: marcar("entrada"))
    btn_mark_out = tk.Button(root, text="Marcar Salida",
                             bg="#ff9800", fg="white", width=14,
                             command=lambda: marcar("salida"))
    btn_clear = tk.Button(root, text="Limpiar", width=10,
                          command=clear_form)

    btn_save.grid(row=row,   column=1, columnspan=2, sticky="w", pady=6)
    btn_update.grid(row=row,   column=3)
    btn_delete_ced.grid(row=row, column=4)
    row += 1
    btn_mark_in .grid(row=row, column=1, columnspan=2, sticky="w")
    btn_mark_out.grid(row=row, column=3)
    btn_clear   .grid(row=row, column=4)
    row += 1

    btn_export1 = tk.Button(root, text="Reg PDF", command=exp_reg_pdf)
    btn_export2 = tk.Button(root, text="Reg XLS", command=exp_reg_xls)
    btn_log     = tk.Button(root, text="Bitácora", command=ver_log)
    btn_export3 = tk.Button(root, text="Bit PDF", command=exp_log_pdf)
    btn_export4 = tk.Button(root, text="Bit XLS", command=exp_log_xls)
    btn_exportar_entradas = tk.Button(root, text="Entradas/Salidas XLS", command=exportar_entradas_salidas)

    btn_export1.grid(row=row, column=1, pady=4)
    btn_export2.grid(row=row, column=2)
    btn_log    .grid(row=row, column=3)
    btn_export3.grid(row=row, column=4)
    btn_export4.grid(row=row, column=5)
    if perfil == "Exportador":
        btn_exportar_entradas.grid(row=row+1, column=1, columnspan=5, pady=4)

    toggle_perm()
    if perfil in ("Super Usuario", "Admin Tipo Super Usuario"):
        on_sede_selected()

# ──────────────── inicio de programa ─────────────────────────
root = tk.Tk()
root.withdraw()
ensure_default_account()
root.after(100, show_login)
root.mainloop()
#!/usr/bin/env python3
# Averabyte Labs – ZKTeco Genesis (GUI 2025-07-05)

# ──────────────── IMPORTS ─────────────────────────────
from __future__ import annotations
import csv, hashlib, inspect, logging, os, pathlib, shutil, threading, atexit
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from pyzk import ZK, const

# ──────────────── LOGGING ─────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname)s: %(message)s',
                    datefmt='%H:%M:%S')

# ──────────────── RUTAS Y ARCHIVOS ───────────────────
BASE_DIR   = pathlib.Path.cwd() / "AVERABYTE_LABS"
BACKUP_DIR = BASE_DIR / "backups"
BASE_DIR.mkdir(exist_ok=True)
BACKUP_DIR.mkdir(exist_ok=True)

CSV_FILE      = BASE_DIR / "registro_usuarios.csv"
BITACORA      = BASE_DIR / "bitacora_acciones.csv"
ACCOUNTS_FILE = BASE_DIR / "accounts.csv"
LOGO_PATH     = BASE_DIR / "logo_averabyte_labs.png"
ICON_PATH     = BASE_DIR / "icon_averabyte_labs.png"



# ──────────────── CONSTANTES Y CONFIG ─────────────────
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

HEADERS = [
    "UID", "Nombre", "C.C.", "Teléfono", "Sede", "Cargo", "Empresa",
    "Permiso", "Fingers", "Fecha Creación", "Fecha Modificación",
    "Huella Entrada", "Huella Salida", "IP"
]
PERFILES = [
    "Super Usuario", "Admin Tipo Super Usuario",
    "Admin por Sede", "Exportador", "Usuario"
]


PERFIL_PRIV = {
    "Super Usuario":            const.USER_ADMIN,
    "Admin Tipo Super Usuario": const.USER_ADMIN,
    "Admin por Sede":           const.USER_ADMIN,
    "Exportador":               const.USER_DEFAULT,
    "Usuario":                  const.USER_DEFAULT,
}

PERM_RIGHTS = {
    "Super Usuario":            dict(create=True, update=True, delete=True, mark=True, export=True, lista=True, viewlog=True),
    "Admin Tipo Super Usuario": dict(create=True, update=True, delete=True, mark=True, export=True, lista=True, viewlog=True),
    "Admin por Sede":           dict(create=False, update=True, delete=False, mark=True, export=True, lista=True, viewlog=True),
    "Exportador":               dict(create=False, update=False, delete=False, mark=False, export=True, lista=False, viewlog=True),
    "Usuario":                  dict(create=False, update=False, delete=False, mark=False, export=False, lista=False, viewlog=False),
}

FINGER_NAMES   = {i:n for i,n in enumerate(["Pulgar D","Índice D","Medio D","Anular D","Meñique D","Pulgar I","Índice I","Medio I","Anular I","Meñique I"])}
FINGER_OPTIONS = [f"{i} – {FINGER_NAMES[i]}" for i in range(10)]

# ──────────────── UTILIDADES CSV / BACKUP ─────────────
sha       = lambda t: hashlib.sha256(str(t).encode()).hexdigest()
read_csv  = lambda p: [] if not p.exists() else list(csv.DictReader(p.open()))

def write_csv(p: pathlib.Path, rows: list[dict]) -> None:
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HEADERS); w.writeheader(); w.writerows(rows)
    backup_csv()

def append_row(p: pathlib.Path, row: dict) -> None:
    empty = not p.exists()
    with p.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=HEADERS)
        if empty: w.writeheader()
        w.writerow(row)
    backup_csv()

def log(act:str, uid:str, name:str, det:str="") -> None:
    first = not BITACORA.exists()
    with BITACORA.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if first: w.writerow(["Fecha","Acción","UID","Nombre","Detalle"])
        w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), act, uid, name, det])

def backup_csv() -> None:
    stamp = datetime.now().strftime("%Y%m%d")
    for src in (CSV_FILE, BITACORA):
        if src.exists():
            dst = BACKUP_DIR / f"{src.stem}_{stamp}.csv"
            if not dst.exists(): shutil.copy2(src, dst)
atexit.register(backup_csv)

# ──────────────── AUTENTICACIÓN ─────────────────────────────

def ensure_default_account() -> None:
    if ACCOUNTS_FILE.exists():
        return
    with ACCOUNTS_FILE.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows([["Usuario","Hash","Perfil"], ["admin", sha("admin123"), "Super Usuario"]])

def check_login(user:str, pwd:str) -> str | None:
    for r in csv.DictReader(ACCOUNTS_FILE.open()):
        if r["Usuario"] == user and r["Hash"] == sha(pwd):
            return r["Perfil"]
    return None

# ──────────────── CONEXIÓN RELOJ ───────────────────────────

def zk_connect(ip:str|None):
    try:
        z = ZK(ip, port=4370, password=0, ommit_ping=True)
        conn = z.connect(); conn.disable_device(); return conn
    except Exception as ex:
        logging.error(ex); return None

# ──────────────── UIDs ─────────────────────────────────────

def next_uid_for_sede(sede:str) -> int | None:
    if sede not in SEDES: return None
    ip = SEDES[sede][0]
    ids = {int(r["UID"]) for r in read_csv(CSV_FILE) if r["UID"].isdigit() and r["Sede"]==sede}
    conn = zk_connect(ip)
    try:
        if conn:
            ids.update(int(u.uid) for u in conn.get_users() if str(u.uid).isdigit())
    finally:
        try: conn.enable_device(); conn.disconnect()
        except: pass
    nxt = (max(ids) if ids else 0) + 1
    return nxt if nxt<=32767 else None

def next_uid_global() -> int:
    ids = {int(r["UID"]) for r in read_csv(CSV_FILE) if r["UID"].isdigit()}
    for ip,_ in SEDES.values():
        c = zk_connect(ip)
        try:
            if c:
                ids.update(int(str(u.uid)) for u in c.get_users() if str(u.uid).isdigit())
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
_show = lambda txt: messagebox.showinfo("Aviso", txt)
exp_reg_pdf = lambda: _show("Exportar PDF usuarios (pendiente)")
exp_reg_xls = lambda: _show("Exportar Excel usuarios (pendiente)")
exp_log_pdf = lambda: _show("Exportar PDF bitácora (pendiente)")
exp_log_xls = lambda: _show("Exportar Excel bitácora (pendiente)")
exportar_entradas_salidas = lambda: _show("Exportar entradas/salidas (pendiente)")
ver_log = lambda: _show("Visor bitácora (pendiente)")

# ──────────────── ROOT PRINCIPAL ───────────────────────────
root = tk.Tk(); root.withdraw()
perfil = None  # ← DEFINE PERFIL Al INICIAR SESIÓN
root.title("Averabyte Labs – ZKTeco Genesis")

# ──────────────── LOGIN GUI ────────────────────────────────

def show_login() -> None:
    dlg = tk.Toplevel(root)              # usa root global
    dlg.title("Login – Averabyte Labs"); dlg.grab_set(); dlg.resizable(False, False)

    tk.Label(dlg, text="Usuario").grid(row=0, column=0, padx=6, pady=4)
    tk.Label(dlg, text="Contraseña").grid(row=1, column=0)

    usr, pwd = tk.StringVar(), tk.StringVar()
    tk.Entry(dlg, textvariable=usr).grid(row=0, column=1)
    tk.Entry(dlg, textvariable=pwd, show="*").grid(row=1, column=1)

    def ingresar():
        perfil = check_login(usr.get(), pwd.get())
        if not perfil:
            messagebox.showerror("Login", "Credenciales inválidas")  # type: ignore
            return
        dlg.destroy(); build_main_gui(perfil)

    tk.Button(dlg, text="Ingresar", command=ingresar).grid(row=2, column=0, columnspan=2, pady=6)

# ──────────────── GUI PRINCIPAL ─────────────────────────────
def build_main_gui(perfil: str) -> None:
    """Genera la ventana principal según el perfil recibido."""
    global root, rights
    rights = PERM_RIGHTS.get(perfil, {})             # permisos

    if not rights:
        messagebox.showerror("Error", "Perfil no reconocido")
        root.destroy()
        return
        
    # --- Construcción de interfaz ---
    root.deiconify()
    root.title(f"Averabyte Labs – ZKTeco Genesis  ({perfil})")
    if LOGO_PATH.exists():
        try:
            img = tk.PhotoImage(file=str(LOGO_PATH))
            lbl = tk.Label(root, image=img)
            lbl.image = img
            lbl.grid(row=0, column=0, rowspan=3, padx=4)
        except tk.TclError:
            pass
    if ICON_PATH.exists():
        try:
            root.iconphoto(False, tk.PhotoImage(file=str(ICON_PATH)))
        except tk.TclError:
            pass

    btn_list = tk.Button(root, text="📋 Lista disp.", command=listar_disp)
    btn_nuevo = tk.Button(root, text="➕ Nuevo", bg="#8bc34a", fg="white",
                          width=10, command=nuevo)
    search_var = tk.StringVar()
    tk.Label(root, text="Buscar UID/C.C.").grid(row=0, column=2, sticky="e")
    tk.Entry(root, textvariable=search_var, width=18).grid(row=0, column=3)
    tk.Button(root, text="Buscar", command=buscar).grid(row=0, column=4, padx=2)
    btn_list.grid(row=0, column=1, padx=2, pady=6)
    btn_nuevo.grid(row=0, column=6, padx=2)

    labels = ["UID", "Nombre", "C.C.", "Teléfono", "Sede", "Cargo", "Empresa", "Permiso"]
    uid_var, nom_var, ced_var, tel_var = (tk.StringVar() for _ in range(4))
    sede_var, cargo_var, emp_var = (tk.StringVar() for _ in range(3))
    perm_var = tk.StringVar(value=PERFILES[-1])
    finger_var = tk.StringVar(value=FINGER_OPTIONS[0])
    huellero_var = tk.StringVar()
    ip_var = tk.StringVar()
    vars_user = [uid_var, nom_var, ced_var, tel_var, sede_var, cargo_var, emp_var]
    row = 1
    for lbl, var in zip(labels, vars_user + [perm_var]):
        tk.Label(root, text=lbl).grid(row=row, column=1, sticky="e")
        if lbl == "Permiso":
            ttk.Combobox(root, textvariable=perm_var, values=PERFILES,
                         state="readonly", width=33)\
                .grid(row=row, column=2, columnspan=3, padx=2, pady=1)
        elif lbl == "Sede":
            if perfil in ("Super Usuario", "Admin Tipo Super Usuario"):
                cb = ttk.Combobox(root, textvariable=sede_var,
                                  values=sorted(SEDES), state="readonly", width=33)
                cb.grid(row=row, column=2, columnspan=3, padx=2, pady=1)
                cb.bind("<<ComboboxSelected>>", on_sede_selected)
            else:
                sede_var.set("COOWORKING")
                huellero_var.set(SEDES["COOWORKING"][1])
                ip_var.set(SEDES["COOWORKING"][0])
                tk.Entry(root, textvariable=sede_var, state="readonly", width=35)\
                    .grid(row=row, column=2, columnspan=3, padx=2, pady=1)
        else:
            e = tk.Entry(root, textvariable=var, width=35)
            e.grid(row=row, column=2, columnspan=3, padx=2, pady=1)
            if lbl == "UID":
                ent_uid = e
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
    ttk.Combobox(root, textvariable=finger_var, values=FINGER_OPTIONS,
                 state="readonly", width=15).grid(row=row, column=2, sticky="w")
    lbl_dedo = tk.Label(root, text=FINGER_OPTIONS[0])
    lbl_dedo.grid(row=row, column=3, columnspan=2, sticky="w")
    finger_var.trace_add("write", on_finger)
    row += 1

    btn_save = tk.Button(root, text="💾 Guardar / Enrolar", bg="#4caf50",
                         fg="white", width=18, command=guardar)
    btn_update = tk.Button(root, text="Actualizar", bg="#2196f3",
                           fg="white", width=12, command=actualizar)
    btn_del = tk.Button(root, text="Eliminar por Cédula", command=eliminar, bg="red", fg="white")
    btn_in = tk.Button(root, text="Marcar Entrada", bg="#009688",
                       fg="white", width=14, command=lambda: marcar("entrada"))
    btn_out = tk.Button(root, text="Marcar Salida", bg="#ff9800",
                        fg="white", width=14, command=lambda: marcar("salida"))
    btn_clear = tk.Button(root, text="Limpiar", width=10, command=clear_form)

    btn_save.grid(row=row, column=1, columnspan=2, sticky="w", pady=6)
    btn_update.grid(row=row, column=3)
    btn_del.grid(row=row, column=4)
    row += 1
    btn_in.grid(row=row, column=1, columnspan=2, sticky="w")
    btn_out.grid(row=row, column=3)
    btn_clear.grid(row=row, column=4)
    row += 1
    
    return row, perfil, rights # retorna fila final, perfil y derechos
    

    # Helper para invocar diálogos desde hilos
    msg = lambda f, *a, **k: root.after(0, lambda: f(*a, **k))

    # ---------- Helpers sede / dedo --------------------------
    def on_sede_selected(_=None) -> None:
        sede = sede_var.get()
        huellero_var.set(SEDES.get(sede, ["", ""])[1])
        ip_var.set(SEDES.get(sede, ["", ""])[0])

    def on_finger(*_) -> None:
        lbl_dedo.config(text=finger_var.get())

    def clear_form() -> None:
        for v in vars_user + [perm_var, finger_var, huellero_var, ip_var]:
            v.set("")
        finger_var.set(FINGER_OPTIONS[0])
        on_finger()
        ent_uid.config(state="normal")

    # ---------- Botón NUEVO ----------------------------------
    def nuevo() -> None:
        clear_form()
        uid_var.set(str(next_uid_global()))
        ent_uid.config(state="readonly")
        if perfil in ("Super Usuario", "Admin Tipo Super Usuario"):
            on_sede_selected()

    # ---------- BUSCAR ---------------------------------------
    def buscar() -> None:
        q = search_var.get().strip().lower()
        if not q:
            return

        # 1) CSV
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
            huellero_var.set(reg.get("Huellero", SEDES[reg["Sede"]][1]))
            ip_var.set(reg.get("IP", SEDES[reg["Sede"]][0]))

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
            w, textvariable=sel, values=sorted(SEDES),
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
                finally:
                    conn.enable_device()
                    conn.disconnect()

            if found:
                uid_var.set(found.uid)
                nom_var.set(found.name)
                ced_var.set(found.user_id)
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

        tk.Button(w, text="Continuar", command=continuar)\
            .grid(row=1, column=0, pady=8)

    # ---------- LISTAR DISPOSITIVO ---------------------------
    def listar_disp() -> None:
        if not rights["lista"]:
            return

        w = tk.Toplevel(root)
        w.title("Selecciona sede")
        sede_sel = tk.StringVar()

        ttk.Combobox(
            w, textvariable=sede_sel, values=sorted(SEDES),
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
                finally:
                    try:
                        conn.enable_device()
                        conn.disconnect()
                    except:
                        pass

            dev_users = leer_dispositivo()
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
            barra = tk.Frame(win); barra.pack(fill="x", pady=2)
            filtro = tk.StringVar()
            tk.Label(barra, text="Filtrar:").pack(side="left")
            tk.Entry(barra, textvariable=filtro, width=20)\
                .pack(side="left", padx=4)

            def refrescar(*_) -> None:
                tv.delete(*tv.get_children())
                pattern = filtro.get().lower()
                rows_local.clear()
                rows_local.update({r["UID"]: r for r in read_csv(CSV_FILE)})

                for u in dev_users:
                    uid = str(u.uid)
                    reg = rows_local.get(uid, {})
                    dedo = reg.get("Fingers", "0").split(";")[0]
                    fila = [
                        uid, u.user_id, u.name, reg.get("Teléfono", ""), sede,
                        reg.get("Cargo", ""), reg.get("Empresa", ""),
                        reg.get("Permiso", ""), SEDES[sede][1], SEDES[sede][0],
                        f"{dedo} – {FINGER_NAMES[int(dedo)]}"
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
                       command=actualizar_dispositivo)\
                .pack(side="left", padx=4)

            filtro.trace_add("write", refrescar)
            refrescar()

            def sel(_evt) -> None:
                it = tv.focus()
                if not it:
                    return
                v = tv.item(it, "values")
                uid_var.set(v[0]); ced_var.set(v[1]); nom_var.set(v[2])
                tel_var.set(v[3]); sede_var.set(v[4]); cargo_var.set(v[5])
                emp_var.set(v[6]); perm_var.set(v[7]); huellero_var.set(v[8])
                ip_var.set(v[9]); finger_var.set(v[10])
                on_finger()
                ent_uid.config(state="readonly")
                win.destroy()

            tv.bind("<Double-1>", sel)

            # Permitir refresco desde otras funciones
            root.current_list_refresh = actualizar_dispositivo

        tk.Button(w, text="Mostrar", command=mostrar)\
            .grid(row=1, column=0, pady=8)

    # ---------- MARCAR ENTRADA / SALIDA ----------------------
    def marcar_entrada():
        if not rights["mark"]:
            return
        marcar("entrada")

    def marcar(tipo):
        if perfil == "Usuario":
            msg(messagebox.showinfo, "Marcación", "Sin permisos")
            return
        uid = uid_var.get().strip()
        cc = str(ced_var.get()).strip()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = zk_connect(ip_var.get())
        marcado = False
        if conn:
            try:
                for u in conn.get_users():
                    if str(u.uid) == uid or str(u.user_id) == cc:
                        try:
                            conn.set_user(uid=int(u.uid), user_id=str(u.user_id),
                                          name=u.name, privilege=u.privilege, group_id=1)
                            marcado = True
                        except:
                            pass
            finally:
                conn.enable_device()
                conn.disconnect()
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

    def enrolar(uid, fid):
        ip = ip_var.get()
        fid_n = fid.split("–")[0].strip()
        if not ip:
            msg(messagebox.showerror, "Conexión", "Sin IP")
            return False
        msg(messagebox.showinfo, "Enrolar", f"Coloque {FINGER_NAMES[int(fid_n)]} 3 veces")
        conn = zk_connect(ip)
        ok = False
        if not conn:
            return False
        try:
            sig = inspect.signature(conn.enroll_user)
            kw = {"uid": int(uid), "user_id": str(ced_var.get())}
            kw["finger" if "finger" in sig.parameters else "fid"] = int(fid_n)
            conn.enroll_user(**kw)
            try:
                tpl = conn.get_user_template(uid=int(uid), fid=int(fid_n))
                ok = bool(tpl and tpl[0])
            except Exception as e:
                logging.warning(e)
            if not ok:
                msg(messagebox.showerror, "Enrolar", "Huella no detectada")
                try:
                    conn.delete_user(uid=int(uid))
                except:
                    pass
                return False
            priv = 0 if perm_var.get() == "Usuario" else PERFIL_PRIV[perm_var.get()]
            conn.set_user(uid=int(uid), user_id=str(ced_var.get()),
                          name=str(nom_var.get())[:24], privilege=int(priv), group_id=1)
            return True
        except Exception as e:
            msg(messagebox.showerror, "Error", str(e))
            return False
        finally:
            conn.enable_device()
            conn.disconnect()

    def guardar():
        if not rights["create"]:
            return
        uid = uid_var.get().strip()
        fid = finger_var.get().split("–")[0].strip()
        if not uid.isdigit() or int(uid) > 32767:
            return messagebox.showerror("UID", "Numérico ≤32767")
        rows = read_csv(CSV_FILE)
        reg = next((r for r in rows if r["UID"] == uid), None)
        def worker():
            if reg:
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

    def actualizar():
        if not rights["update"]:
            return
        uid = uid_var.get().strip()
        conn = zk_connect(ip_var.get())
        if not conn:
            return
        try:
            conn.set_user(uid=int(uid), user_id=str(ced_var.get()),
                          name=str(nom_var.get())[:24],
                          privilege=int(PERFIL_PRIV[perm_var.get()]),
                          group_id=1)
        except Exception as e:
            msg(messagebox.showerror, "Error", str(e))
            return
        finally:
            conn.enable_device()
            conn.disconnect()
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

    def eliminar():
        if not rights["delete"]:
            return

        uid_txt = uid_var.get().strip()
        cc_txt  = str(ced_var.get()).strip()

        modo_uid = uid_txt.isdigit() and int(uid_txt) > 32767
        if modo_uid:
            llave = uid_txt
            pregunta = f"Eliminar usuario con UID {llave} (fuera de rango)?"
        else:
            if not cc_txt:
                return messagebox.showerror("Eliminar", "Ingresa la cédula")
            llave = cc_txt
            pregunta = f"Eliminar usuario con cédula {llave}?"

        if not messagebox.askyesno("Confirmar", pregunta):
            return

        conn = zk_connect(ip_var.get())
        try:
            if conn:
                for u in conn.get_users():
                    if (modo_uid and str(u.uid) == uid_txt) or (not modo_uid and str(u.user_id) == cc_txt):
                        conn.delete_user(uid=int(u.uid))
                        break
        finally:
            if conn:
                conn.enable_device()
                conn.disconnect()

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

        if hasattr(root, "current_list_refresh") and callable(root.current_list_refresh):
            root.current_list_refresh()


# --- Botones de exportación / bitácora --------------------
row = 0  

frm_inferior = tk.Frame(root)
frm_inferior.grid(row=row, column=0, columnspan=7, pady=10, sticky="w")
row += 1
tk.Label(frm_inferior, text="Acciones:").pack(side="left", padx=4)

frm_acciones = tk.Frame(frm_inferior)
frm_acciones.pack(pady=4)

if rights.get("create"):
    tk.Button(frm_acciones, text="✅ Guardar / Enrolar", bg="green", fg="white",
              command=guardar).grid(row=0, column=0, padx=4)

if rights.get("update"):
    tk.Button(frm_acciones, text="Actualizar", bg="dodgerblue", fg="white",
              command=actualizar).grid(row=0, column=1, padx=4)

if rights.get("delete"):
    tk.Button(frm_acciones, text="Eliminar por Cédula", bg="red", fg="white",
              command=eliminar).grid(row=0, column=2, padx=4)

if rights.get("mark"):
    tk.Button(frm_acciones, text="📥 Marcar Entrada", bg="turquoise", fg="black",
              command=lambda: marcar("entrada")).grid(row=0, column=3, padx=4)
    tk.Button(frm_acciones, text="📤 Marcar Salida", bg="orange", fg="black",
              command=lambda: marcar("salida")).grid(row=0, column=4, padx=4)

tk.Button(frm_acciones, text="🧹 Limpiar", command=clear_form)\
    .grid(row=0, column=5, padx=4)

frm_export = tk.Frame(frm_inferior)
frm_export.pack(pady=4)

if rights.get("export"):
    tk.Button(frm_export, text="📄 Reg PDF", command=exp_reg_pdf)\
        .grid(row=0, column=0, padx=4)
    tk.Button(frm_export, text="📊 Reg XLS", command=exp_reg_xls)\
        .grid(row=0, column=1, padx=4)

if rights.get("viewlog"):
    tk.Button(frm_export, text="📝 Bitácora", command=ver_log)\
        .grid(row=0, column=2, padx=4)
    tk.Button(frm_export, text="📄 Bit PDF", command=exp_log_pdf)\
        .grid(row=0, column=3, padx=4)
    tk.Button(frm_export, text="📊 Bit XLS", command=exp_log_xls)\
        .grid(row=0, column=4, padx=4)

if perfil == "Exportador":
    tk.Button(frm_export, text="📤 Entradas/Salidas XLS",
              command=exportar_entradas_salidas)\
        .grid(row=1, column=0, columnspan=5, pady=6)

frm_resumen = tk.Frame(root)
frm_resumen.grid(row=row, column=0, columnspan=7, pady=6, sticky="w")
row += 1

lbl_resumen = tk.Label(
    frm_resumen,
    text="Listo",
    font=("Segoe UI", 9, "italic")
)
lbl_resumen.pack()

def actualizar_resumen(mensaje: str | None = None) -> None:
    try:
        registros = read_csv(CSV_FILE)
        total = len(registros)
        ultimo_uid = max((int(r["UID"]) for r in registros if r["UID"].isdigit()), default=0)
        fecha_mod = datetime.fromtimestamp(os.path.getmtime(CSV_FILE)).strftime("%Y-%m-%d %H:%M:%S")

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

    # Hacemos accesible la función desde root
root.actualizar_resumen = actualizar_resumen
actualizar_resumen("Sistema listo")

if perfil == "Exportador":
    tk.Button(
        root,
        text="Entradas/Salidas XLS",
        command=exportar_entradas_salidas
    ).grid(row=row+1, column=1, columnspan=5, pady=4)

if perfil in ("Super Usuario", "Admin Tipo Super Usuario"):
    on_sede_selected()

# ──────────────── INICIO APP ────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    ensure_default_account()
    root.after(100, show_login)
    root.mainloop()
    logging.info("Aplicación cerrada")
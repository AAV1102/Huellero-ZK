from pyzk import ZK

def listar_usuarios():
    try:
        zk = ZK("192.168.199.246", port=4370)
        conn = zk.connect()
        conn.disable_device()
        users = conn.get_users()
        print("Usuarios enrolados en el reloj:")
        for user in users:
            print(f"UID: {user.uid}, ID: {user.user_id}, Nombre: {user.name}")
        conn.enable_device()
        conn.disconnect()
    except Exception as e:
        print("Error al conectar o consultar:", e)

if __name__ == "__main__":
    listar_usuarios()
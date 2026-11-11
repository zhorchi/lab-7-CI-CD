import subprocess


def lookup_user(cursor, user_id: str):
    cursor.execute(
        "SELECT name FROM users WHERE id = ?",
        (user_id,),
    )
    return cursor.fetchone()


def check_host(host: str):
    return subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        capture_output=True,
        text=True,
    )

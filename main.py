import subprocess, json

MOUNT = 'secret'


def list_keys(path):
    try:
        out = subprocess.check_output(
            f"vault kv list -format=json {MOUNT}/{path}", shell=True
        )
        return json.loads(out) or []
    except subprocess.CalledProcessError:
        return None


def get_value(path):
    out = subprocess.check_output(
        f"vault kv get -format=json {MOUNT}/{path}", shell=True
    )
    return json.loads(out)


def explore():
    path = ''
    while True:
        keys = list_keys(path)
        if keys is None:
            print(json.dumps(get_value(path), indent=2))
            input("[Enter] to go back")
            path = '/'.join(path.split('/')[:-1])
            continue
        print(f"Path: /{path}")
        for i, k in enumerate(keys): print(f"{i}: {k}")
        cmd = input("[number] to enter, b-back, q-quit: ")
        if cmd == 'q': break
        if cmd == 'b': path = '/'.join(path.split('/')[:-1])
        elif cmd.isdigit() and int(cmd) < len(keys):
            sel = keys[int(cmd)]
            path = f"{path}/{sel}".strip('/')
        else:
            print("Niepoprawne.")


if __name__ == '__main__':
    explore()

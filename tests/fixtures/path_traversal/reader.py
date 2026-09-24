import os


def read_file(path):
    base = '/tmp/deepaudit-data'
    os.makedirs(base, exist_ok=True)
    return open(os.path.join(base, path)).read()

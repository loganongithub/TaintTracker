# expect: path-traversal line 3
def load(name):
    with open("/srv/files/" + name) as f:
        return f.read()

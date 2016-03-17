def number(obj):
    try:
        return int(obj)
    except ValueError:
        try:
            return float(obj)
        except ValueError:
            return obj


def resolve(kx, var, replacefn=None, idset=None):
    idset = idset or set()
    for k, v in kv(kx):
        if isinstance(v, (str, unicode)):
            if replacefn is not None:
                v = replacefn(v)
            # check for direct replacement first
            vx = v.strip()[1:-1]
            if vx in var:
                kx[k] = number(var[vx])
            else:
                kx[k] = v.format(**var)
            continue
        if isinstance(v, (int, long, bool)):
            continue
        vid = id(v)
        if vid not in idset:
            idset.add(vid)
            resolve(v, var, replacefn=replacefn, idset=idset)


def kv(obj):
    if isinstance(obj, dict):
        return obj.iteritems()
    elif isinstance(obj, list):
        return enumerate(obj)
    elif obj is None:
        return enumerate([])
    else:
        raise Exception("{} {}".format(obj, type(obj)))

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


def isElementry(val):
    return isinstance(
        val,
        (int, long, bool, str, unicode))


def isTerminal(val):
    if isElementry(val) is True:
        return True
    if isinstance(val, list):
        return all(isElementry(vv) for vv in val)

    return False


def cfgmerge(dest, src):
    dest_keys = dest.keys()
    for key in src.keys():
        if key == src.idfield:
            continue
        val = src[key]
        if key == 'value' or isTerminal(val.obj):
            dest[key] = val.obj
            continue
        if key in dest_keys:
            cfgmerge(dest[key], src[key])
        else:
            print(
                "{} key {} is missing from {} ".format(
                    src,
                    key,
                    dest_keys))
            dest[key] = val.obj


class Cfg(object):
    def __init__(self, obj, idfield='identifier', key=""):
        self.obj = obj
        self.idfield = idfield
        self.key = key

    def __getitem__(self, key):
        if isinstance(self.obj, dict):
            return Cfg(self.obj[key], self.idfield, self.key+"."+key)
        if isinstance(self.obj, list):
            if isinstance(key, (str, unicode)):
                val = next(vv for vv in self.obj if vv[self.idfield] == key)
                return Cfg(val, self.idfield, self.key+"."+key)
            elif isinstance(key, (int, long)):
                return Cfg(self.obj[key], self.idfield, self.key+"."+key)

    def __setitem__(self, key, val):
        if isinstance(self.obj, dict):
            self.obj[key] = val

    def keys(self):
        if isinstance(self.obj, dict):
            return self.obj.keys()
        elif isinstance(self.obj, list):
            return [v[self.idfield] for v in self.obj]

    def get(self, jpath):
        vx = self
        for comp in jpath.split('.'):
            if comp == '':
                continue
            vx = vx[comp]
        return vx

    def __repr__(self):
        return self.key

TYPE_PID = "pid" # for backward compatibility v1.3.3
TYPE_EID=  "eid"
TYPE_DEGREE = "degree"
TYPE_ENROLLMENT = "enrollment"


def get_type_from_key(key: str):
    if TYPE_EID in key:
        return TYPE_EID
    if TYPE_PID in key:
        return TYPE_PID
    elif TYPE_DEGREE in key:
        return TYPE_DEGREE
    elif TYPE_ENROLLMENT in key:
        return TYPE_ENROLLMENT
    return None

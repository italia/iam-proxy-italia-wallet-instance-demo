

TYPE_PID = "pid"
TYPE_DEGREE="degree"
TYPE_ENROLLMENT="enrollment"

def get_type_from_key(key: str):
    if TYPE_PID in key:
        return TYPE_PID
    elif TYPE_DEGREE in key:
        return TYPE_DEGREE
    elif TYPE_ENROLLMENT in key:
        return TYPE_ENROLLMENT
    return None

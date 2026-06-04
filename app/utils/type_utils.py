

TYPE_PID = "pid"
TYPE_DEGREE="degree"
TYPE_ENROLLMENT="enrollment"

def get_type_from_key(key: str):
    if key.contains(TYPE_PID):
        return TYPE_PID
    elif key.contains(TYPE_DEGREE):
        return TYPE_DEGREE
    elif key.contains(TYPE_ENROLLMENT):
        return TYPE_ENROLLMENT
    return None

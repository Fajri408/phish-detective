def convert_keys_to_int(obj):
    if isinstance(obj, dict):
        return {
            (
                int(k) if k.isdigit() or (k.startswith("-") and k[1:].isdigit()) else k
            ): convert_keys_to_int(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [convert_keys_to_int(i) for i in obj]
    return obj

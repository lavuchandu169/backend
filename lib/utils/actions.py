import random
import string

def generate_alphanumeric_code(length=10):
    characters = string.ascii_letters + string.digits
    code = ''.join(random.choices(characters, k=length))
    return code
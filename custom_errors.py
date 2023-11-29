import os
from dotenv import load_dotenv

load_dotenv()


class MissingEnvironmentVariable(Exception):
    pass


def get_env_var(var_name: str):
    try:
        env_var = os.getenv(var_name)
        if env_var is None:
            raise MissingEnvironmentVariable(f"{var_name} does not exist")

        return env_var
    except KeyError:
        raise MissingEnvironmentVariable(f"{var_name} does not exist")

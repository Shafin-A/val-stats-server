from sqlmodel import Session, create_engine

from custom_errors import get_env_var

DATABASE_URL = get_env_var('DATABASE_URL')

engine = create_engine(DATABASE_URL)


def get_session():
    with Session(engine) as session:
        yield session

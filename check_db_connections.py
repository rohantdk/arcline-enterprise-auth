from sqlalchemy import create_engine, text
from dotenv import load_dotenv
import os


load_dotenv()

connections = [
    "ARCLINE_TEST_ADMIN_DATABASE_URL",
    "ARCLINE_TEST_RUNTIME_DATABASE_URL",
]

for name in connections:
    url = os.getenv(name)
    print(f"\nChecking {name}...")

    if not url:
        print("FAILED: Environment variable is missing.")
        continue

    engine = None

    try:
        engine = create_engine(
            url,
            connect_args={"connect_timeout": 5},
        )

        with engine.connect() as connection:
            result = connection.execute(
                text("SELECT current_user, current_database()")
            ).one()

            print(f"CONNECTED: user={result[0]}, database={result[1]}")

    except Exception as error:
        print(f"FAILED: {type(error).__name__}")
        print(f"DETAIL: {str(error).splitlines()[0][:250]}")

    finally:
        if engine is not None:
            engine.dispose()

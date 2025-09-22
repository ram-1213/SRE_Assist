from sqlalchemy import create_engine, MetaData, Table, Column, Integer, Float, String, Text, Boolean, text
from sqlalchemy.exc import OperationalError

# Replace with your actual DB path
DATABASE_URL = "sqlite:///database/secure_llm.db"

engine = create_engine(DATABASE_URL)
metadata = MetaData()  # no bind here

# Reflect the existing table
security_analysis = Table('security_analysis', metadata, autoload_with=engine)

# Helper function to add column if it doesn't exist
def add_column_if_not_exists(table, column):
    if column.name not in table.c:
        try:
            with engine.begin() as conn:  # Use a connection context
                sql = f'ALTER TABLE {table.name} ADD COLUMN {column.name} {column.type.compile(engine.dialect)}'
                if column.default is not None:
                    sql += f' DEFAULT {column.default.arg if column.default else "NULL"}'
                conn.execute(text(sql))
            print(f"Added column '{column.name}'")
        except OperationalError as e:
            print(f"Could not add column '{column.name}': {e}")

# Define the new columns
new_columns = [
    Column('iterations_performed', Integer, default=0),
    Column('initial_vulnerabilities', Integer, default=0),
    Column('final_vulnerabilities', Integer, default=0),
    Column('sanitization_successful', Boolean, default=False),
    Column('ml_analysis_results', Text, default=None),
    Column('advanced_tools_used', Text, default=None)
]

# Apply migration
for col in new_columns:
    add_column_if_not_exists(security_analysis, col)

print("Migration complete.")

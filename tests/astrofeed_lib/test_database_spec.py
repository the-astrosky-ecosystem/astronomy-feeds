from inspect import isclass
from warnings import warn

from peewee import IntegerField, BigIntegerField, CharField, BooleanField, DateTimeField

import astrofeed_lib.database  # importing as a whole module to search with dir
from astrofeed_lib.database import proxy, BaseModel, DBConnection
from astrofeed_lib.database import (
    Account,
    Post,
    BotActions,
    ModActions,
    SubscriptionState,
    ActivityLog,
)

#
# setup
#

# dictionary of tables/model classes to check compability for, with bool indicating checked status
tables_to_test = {
    "account": False,
    "post": False,
    "modactions": False,
    "botactions": False,
    "subscriptionstate": False,
    "activitylog": False,
}

# list of Peewee model classes defined in database module
model_names = []
for model_name in dir(astrofeed_lib.database):
    model = getattr(astrofeed_lib.database, model_name)
    if isclass(model) and issubclass(model, BaseModel) and model != BaseModel:
        model_names.append(model.__name__.lower())

# list of tables in the database
with DBConnection():
    table_names = proxy.get_tables()

# dictionary for translating postgres type labels to Peewee field types
postgres_type_label_to_peewee_field_type = {
    "integer": IntegerField,
    "bigint": BigIntegerField,
    "character varying": CharField,
    "boolean": BooleanField,
    "timestamp without time zone": DateTimeField,
}


#
# utility functions
#
def register_test_function_execution(table_name: str):
    if table_name in tables_to_test.keys():
        tables_to_test[table_name] = True
    else:
        warn(
            f"{table_name} test function exists, but was not specified in list of tables to test."
        )


def get_database_table_info(table_name: str):
    """Fetch and return certain column info from specified table in astrofeed_lib.database.proxy database (postgres presumed)."""
    with DBConnection():
        cursor = proxy.execute_sql(
            "SELECT column_name, data_type, character_maximum_length, is_nullable, column_default "
            "FROM information_schema.columns "
            f"WHERE table_name = '{table_name}' AND table_schema = 'public';"
        )

        names, typelabels, maxlengths, nullables, has_defaults = [], [], [], [], []
        for row in cursor.fetchall():
            column_name, data_type, max_length, is_nullable, default_value = row
            if column_name == "id":  # don't need this column
                continue
            names.append(column_name)
            typelabels.append(data_type)
            maxlengths.append(max_length)
            nullables.append(is_nullable == "YES")
            has_defaults.append(default_value is not None)

    return names, typelabels, maxlengths, nullables, has_defaults


def check_peewee_spec_compatibility(
    model: BaseModel,
    names: list[str],
    typelabels: list[str],
    maxlengths: list[int],
    nullables: list[bool],
    has_defaults: list[bool],
):
    """Assert compatibility of model properties in specified peewee model class with specified table column info."""
    for name, typelabel, maxlength, nullable, has_default in zip(
        names, typelabels, maxlengths, nullables, has_defaults
    ):
        assert hasattr(model, name)
        column = getattr(model, name)
        assert type(column) is postgres_type_label_to_peewee_field_type[typelabel]
        if maxlength is not None:
            assert column.max_length == maxlength
        if (
            not has_default and not nullable
        ):  # if the column is not nullable and has no default value, cannot be null in peewee
            assert not column.null


#
# test functions
#


def test_peewee_spec_coverage():
    """Tests that the peewee spec has a model class defined for each table in database."""
    for table_name in table_names:
        assert table_name in model_names


def test_account():
    """Tests compatibility between specs for peewee Account model class and database Account table."""
    # check that this test function is wanted, and mark that it is defined if so
    register_test_function_execution("account")

    # get info about the account table
    table_info = get_database_table_info("account")

    # check for parity with model class
    check_peewee_spec_compatibility(Account, *table_info)


def test_post():
    """Tests compatibility between specs for peewee Post model class and database Post table."""
    # check that this test function is wanted, and mark that it is defined if so
    register_test_function_execution("post")

    # get info about the account table
    table_info = get_database_table_info("post")

    # check for parity with model class
    check_peewee_spec_compatibility(Post, *table_info)


def test_botactions():
    """Tests compatibility between specs for peewee BotActions model class and database BotActions table."""
    # check that this test function is wanted, and mark that it is defined if so
    register_test_function_execution("botactions")

    # get info about the account table
    table_info = get_database_table_info("botactions")

    # check for parity with model class
    check_peewee_spec_compatibility(BotActions, *table_info)


def test_modactions():
    """Tests compatibility between specs for peewee ModActions model class and database ModActions table."""
    # check that this test function is wanted, and mark that it is defined if so
    register_test_function_execution("modactions")

    # get info about the account table
    table_info = get_database_table_info("modactions")

    # check for parity with model class
    check_peewee_spec_compatibility(ModActions, *table_info)


def test_subscriptionstate():
    """Tests compatibility between specs for peewee SubscriptionState model class and database SubscriptionState table."""
    # check that this test function is wanted, and mark that it is defined if so
    register_test_function_execution("subscriptionstate")

    # get info about the account table
    table_info = get_database_table_info("subscriptionstate")

    # check for parity with model class
    check_peewee_spec_compatibility(SubscriptionState, *table_info)


def test_activitylog():
    """Tests compatibility between specs for peewee ActivityLog model class and database ActivityLog table."""
    # check that this test function is wanted, and mark that it is defined if so
    register_test_function_execution("activitylog")

    # get info about the account table
    table_info = get_database_table_info("activitylog")

    # check for parity with model class
    check_peewee_spec_compatibility(ActivityLog, *table_info)


def test_test_case_coverage():
    """Warns if there were any intended test case functions was executed defined for each specified table."""
    for table_name, tested in tables_to_test.items():
        if not tested:
            warn(
                f"{table_name} is listed as a table that should be tested, but no test function was recorded as executing for it."
            )

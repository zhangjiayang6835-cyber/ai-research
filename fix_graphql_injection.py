import graphene
from graphql import validate, parse
from graphql.language.printer import print_ast
from graphql.utils.schema_printer import print_schema

# Assume we have a database session and an ORM model
from models import User
from database import db_session

class UserType(graphene.ObjectType):
    id = graphene.Int()
    name = graphene.String()
    email = graphene.String()

class Query(graphene.ObjectType):
    user = graphene.Field(UserType, id=graphene.Int(required=True))

    def resolve_user(self, info, id):
        # Use parameterized query to prevent injection
        user = db_session.query(User).filter(User.id == id).first()
        return user

schema = graphene.Schema(query=Query)

def execute_secure_query(query_string, variables=None):
    # Validate query against schema before execution
    document = parse(query_string)
    errors = validate(schema, document)
    if errors:
        raise Exception('Invalid query: {}'.format(errors))
    # Execute with variables (never interpolate user input directly into query string)
    result = schema.execute(query_string, variables=variables)
    return result

# Example usage:
# result = execute_secure_query('query ($id: Int!) { user(id: $id) { name } }', variables={'id': 1})
# print(result.data)
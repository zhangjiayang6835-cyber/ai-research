```python
import graphene
from graphql.execution.base import ResolveInfo
from flask_graphql_auth import get_jwt_identity

class OrderItem(graphene.ObjectType):
    price = graphene.Float()

class Order(graphene.ObjectType):
    items = graphene.List(OrderItem)

class User(graphene.ObjectType):
    orders = graphene.Field(lambda: Order, resolver=resolve_orders)

def resolve_user(root, info: ResolveInfo, id: int):
    user_id = get_jwt_identity()
    if not user_id or user_id != id:
        raise Exception("Unauthorized")
    return {"id": id}

def resolve_orders(user: dict, info: ResolveInfo) -> list[Order]:
    user_id = get_jwt_identity()
    if not user_id or user["id"] != int(user_id):
        raise Exception("Unauthorized")
    # Simulate database query
    orders = [
        Order(
            items=[
                OrderItem(price=i)
                for i in range(10)  # Example data, replace with actual data source
            ]
        )
        for _ in range(5)  # Example data, replace with actual data source
    ]
    return orders

class Query(graphene.ObjectType):
    user = graphene.Field(User, id=graphene.Int(required=True))

schema = graphene.Schema(query=Query)

def main():
    query = '''
      query GetUserOrders($id: Int!) {
        user(id: $id) {
          orders {
            items {
              price
            }
          }
        }
      }
    '''

    variables = {"id": 123}

    result = schema.execute(query, variable_values=variables)
    print(result.data)

if __name__ == "__main__":
    main()
```

This code addresses the IDOR vulnerability by ensuring that each resolver checks data ownership using the authentication context provided by `get_jwt_identity()`. The `resolve_orders` function ensures that only the user who owns the requested data can access it.
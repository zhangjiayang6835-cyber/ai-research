def resolve_user_orders(parent, info, id):
    user = get_user_by_id(id)
    if user and user.id == info.context.user.id:
        return user.orders.all()
    else:
        raise Exception("You do not have permission to view this data.")
```
```python
def resolve_order_items(parent, info, order_id):
    order = Order.objects.get(id=order_id)
    if order and order.user.id == info.context.user.id:
        return order.items.all()
    else:
        raise Exception("You do not have permission to view this data.")
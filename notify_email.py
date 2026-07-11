def resolve_user_orders(parent, info, id):
    user = get_user_by_id(id)
    if user and user.id == info.context.user.id:
        return user.orders
    else:
        return []
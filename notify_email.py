def deduct_balance(user_id, amount):
    from sqlalchemy.orm import sessionmaker
    from your_database_model import User

    Session = sessionmaker(bind=your_engine)
    session = Session()

    user = session.query(User).with_for_update().get(user_id)
    if not user:
        return False

    original_balance = user.balance
    new_balance = original_balance - amount

    if new_balance < 0:
        session.rollback()
        return False

    user.balance = new_balance
    session.commit()

    return True
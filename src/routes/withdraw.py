from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from models import db, Withdrawal

withdraw_bp = Blueprint('withdraw', __name__)

@withdraw_bp.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    # Add security headers specifically for withdrawal page
    response = None
    if request.method == 'POST':
        # Require secondary confirmation for critical operations
        confirmation = request.form.get('confirm_withdrawal')
        if not confirmation or confirmation != 'CONFIRM':
            flash('Please confirm the withdrawal by typing CONFIRM', 'warning')
            return render_template('withdraw.html')
        
        amount = request.form.get('amount')
        address = request.form.get('address')
            db.session.add(withdrawal)
            db.session.commit()
            flash('Withdrawal request submitted successfully', 'success')
            response = redirect(url_for('dashboard'))
        else:
            flash('Invalid withdrawal details', 'error')
            response = render_template('withdraw.html')
    else:
        response = render_template('withdraw.html')
    
    return response
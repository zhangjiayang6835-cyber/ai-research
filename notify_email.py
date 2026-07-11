from jinja2 import Template, Environment, PackageLoader

template_env = Environment(loader=PackageLoader('your_package_name', 'templates'))

def send_email(user_input):
    template = template_env.get_template('email_template.html')
    safe_context = {'user_input': user_input}
    safe_template = template.render(safe_context)
    # Proceed with sending the email
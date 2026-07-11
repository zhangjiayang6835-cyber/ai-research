```python
import jinja2.sandbox
from jinja2 import Environment, PackageLoader, select_autoescape

class SafeEnvironment(jinja2.sandbox.SandboxedEnvironment):
    def __init__(self):
        super().__init__()
        self.disable_functions(['__class__', '__mro__', '__subclasses__'])

def main():
    # Define a safe template using the custom environment
    env = SafeEnvironment(
        loader=PackageLoader('your_package', 'templates'),
        autoescape=select_autoescape(['html', 'xml'])
    )

    template = env.get_template('safe_email.html')

    # Safe context with user input
    context = {
        'user_input': 'World'
    }

    # Render the template safely without exposing it to potential vulnerabilities
    rendered_email = template.render(context)
    print(rendered_email)

if __name__ == "__main__":
    main()
```

```python
# templates/safe_email.html
<!DOCTYPE html>
<html>
<head>
    <title>Hello Email</title>
</head>
<body>
    <p>Hello {{ user_input }}</p>
</body>
</html>
```
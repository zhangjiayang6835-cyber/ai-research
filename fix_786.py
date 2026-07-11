```python
import jinja2

def main():
    # Safe template rendering example
    safe_template = "Hello {{ user_name }}"
    
    # Disable dangerous functions and classes in Jinja2 sandbox
    disabled_functions = set(dir(jinja2)) - {'Template', 'Environment', 'PackageLoader', 'SelectExtension'}
    for func in disabled_functions:
        if hasattr(jinja2, '__dict__'):
            delattr(getattr(jinja2, '__dict__'), func)
    
    # Pre-compile the template
    env = jinja2.Environment()
    compiled_template = env.from_string(safe_template)
    
    # Safe rendering with user input
    user_input = "World"
    result = compiled_template.render(user_name=user_input)
    print(result)

if __name__ == "__main__":
    main()
```
```python
import jinja2

def main():
    # Safe template rendering example
    safe_template = "Hello {{ user_name }}"
    
    # Disable dangerous functions and classes in Jinja2 sandbox
    disabled_classes = set(dir(object)) - {'object', 'str'}
    for cls in disabled_classes:
        if hasattr(jinja2, '__dict__'):
            delattr(getattr(jinja2, '__dict__'), f'__{cls}__')
    
    # Disable dangerous methods in classes
    for func in dir(jinja2):
        if (func.startswith('__') and func.endswith('__') and 
                not any([x in func for x in disabled_classes])):
            delattr(jinja2, func)
    
    # Pre-compile the template
    env = jinja2.Environment()
    compiled_template = env.from_string(safe_template)
    
    # Safe rendering with user input
    user_input = "World"
    result = compiled_template.render(user_name=user_input)
    print(result)

if __name__ == "__main__":
    main()
```
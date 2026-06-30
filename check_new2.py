import yaml, yaml.constructor
import os
import sys

for i in [17,18,19,20,21,22,23,24,25,26,27,28]:
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return None
    return yaml.safe_load(open(filepath, 'r'))

if __name__ == "__main__":
    if len(sys.argv) > 1:
    except Exception as e:
        print(f"=== #{i} === ERROR: {e}")
    print()

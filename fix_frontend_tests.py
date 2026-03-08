import os
import re

def fix_imports():
    # Base directory for the tests that were moved
    base_dir = r'c:\Users\EYanez\OneDrive - ORBE INVERSIONES S.A\Documentos\GitHub\vuln-app-wazuh\frontend\tests'
    if not os.path.exists(base_dir):
        print(f"Directory {base_dir} does not exist.")
        return

    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.spec.js'):
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # 1. Replace relative paths to src with @/
                    # Usually tests had things like ../../../application/services/...
                    # Now that they are in /tests, those would be ../src/application/services/... 
                    # But using @/ is better.
                    
                    # Pattern matches things like: from '../../../' or from '../../' or from '../' or from 'src/'
                    # and replaces them with @/
                    new_content = re.sub(r"(from\s+['\"])(?:\.\./|src/)+", r"\1@/", content)
                    new_content = re.sub(r"(vi\.mock\(['\"])(?:\.\./|src/)+", r"\1@/", new_content)
                    
                    # 2. Cleanup double @// if any
                    new_content = new_content.replace("@//@/", "@/").replace("@/@/", "@/")
                    
                    if new_content != content:
                        with open(path, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        print(f"Fixed imports in: {path}")
                    else:
                        print(f"No changes needed for: {path}")
                except Exception as e:
                    print(f"Error processing {path}: {e}")

if __name__ == "__main__":
    fix_imports()

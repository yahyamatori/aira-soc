# Find all usages of 'r' as a variable that might cause issues
with open('analyzers/attack_analyzer.py', 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

# Look for patterns like "r." or "r[" or "r(" that suggest r is being used as a variable
for i, line in enumerate(lines, 1):
    # Skip comments and strings
    stripped = line.strip()
    if stripped.startswith('#'):
        continue
    
    # Look for 'r.' but not 're.' or 'return'
    if 'r.' in line and 're.' not in line and 'return' not in line:
        # Make sure it's not in a string
        if not ('"' in line or "'" in line):
            print(f"Line {i}: {line.rstrip()}")
    
    # Look for 'r[' which suggests indexing a variable
    if 'r[' in line:
        print(f"Line {i} [r[ : {line.rstrip()}")
    
    # Look for function calls like r(
    if 'r(' in line and 're(' not in line and 'print(' not in line:
        print(f"Line {i} r( : {line.rstrip()}")

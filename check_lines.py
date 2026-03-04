# Check for potential issues in attack_analyzer.py
with open('analyzers/attack_analyzer.py', 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

# Find lines with potential issues (f-strings, variables named r, etc.)
for i, line in enumerate(lines, 1):
    # Look for f-strings or issues with 'r' variable
    if 'f"' in line or "f'" in line:
        print(f"Line {i}: {line.rstrip()}")
    if '= r' in line and 'r"' not in line:
        print(f"Line {i} (possible r var): {line.rstrip()}")

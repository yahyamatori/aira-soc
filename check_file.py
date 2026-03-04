import re

# Read file as binary
with open('analyzers/attack_analyzer.py', 'rb') as f:
    content = f.read()

# Find all positions of "r'" (not preceded by another letter)
problematic = []
for i in range(len(content) - 1):
    if content[i:i+2] == b"r'":
        # Check context - show 20 chars around
        start = max(0, i - 30)
        end = min(len(content), i + 50)
        context = content[start:end]
        try:
            context_str = context.decode('utf-8')
        except:
            context_str = context.decode('latin-1', errors='replace')
        print(f"Position {i}: ...{context_str}...")
        print()
        if len(problematic) > 5:
            break

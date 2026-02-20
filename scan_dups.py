"""Scan app.py for duplicate callback outputs using AST parsing."""
import ast
import sys
from collections import defaultdict

with open('app.py', 'r', encoding='utf-8') as f:
    source = f.read()

tree = ast.parse(source)

def extract_outputs(node):
    """Extract (id, property, allow_duplicate) from an Output() call or list of Output() calls."""
    results = []
    
    if isinstance(node, ast.Call):
        # Check if this is Output(...)
        func = node.func
        func_name = ''
        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr
        
        if func_name == 'Output':
            oid = oprop = None
            allow_dup = False
            
            # Positional args
            if len(node.args) >= 2:
                if isinstance(node.args[0], ast.Constant):
                    oid = node.args[0].value
                if isinstance(node.args[1], ast.Constant):
                    oprop = node.args[1].value
            
            # Keyword args
            for kw in node.keywords:
                if kw.arg == 'allow_duplicate' and isinstance(kw.value, ast.Constant):
                    allow_dup = kw.value.value
                if kw.arg == 'component_id' and isinstance(kw.value, ast.Constant):
                    oid = kw.value.value
                if kw.arg == 'component_property' and isinstance(kw.value, ast.Constant):
                    oprop = kw.value.value
            
            # Also check 3rd positional arg
            if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
                # This would be unusual but check anyway
                pass
            
            if oid and oprop:
                results.append((oid, oprop, allow_dup, node.lineno))
    
    elif isinstance(node, ast.List):
        for elt in node.elts:
            results.extend(extract_outputs(elt))
    
    return results

# Find all callback decorators
all_outputs = defaultdict(list)

for node in ast.walk(tree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call):
                fname = ''
                if isinstance(dec.func, ast.Name):
                    fname = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    fname = dec.func.attr
                
                if fname == 'callback' and dec.args:
                    outputs = extract_outputs(dec.args[0])
                    for (oid, oprop, allow_dup, lineno) in outputs:
                        all_outputs[(oid, oprop)].append({
                            'func': node.name,
                            'line': lineno,
                            'allow_dup': allow_dup
                        })

# Also find clientside_callback calls
for node in ast.walk(tree):
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        call = node.value
        if isinstance(call.func, ast.Attribute) and call.func.attr == 'clientside_callback':
            # clientside_callback(js_string, Output(...), [Input(...)], ...)
            # The Output is typically the second positional arg
            if len(call.args) >= 2:
                outputs = extract_outputs(call.args[1])
                for (oid, oprop, allow_dup, lineno) in outputs:
                    all_outputs[(oid, oprop)].append({
                        'func': 'clientside_callback',
                        'line': lineno,
                        'allow_dup': allow_dup
                    })

print(f"Total unique (id, property) pairs: {len(all_outputs)}")
print()

conflict_count = 0
for (oid, oprop), instances in sorted(all_outputs.items()):
    if len(instances) > 1:
        all_ok = all(i['allow_dup'] for i in instances)
        tag = 'OK' if all_ok else '*** CONFLICT ***'
        if not all_ok:
            conflict_count += 1
        print(f'[{tag}] {oid}.{oprop}:')
        for inst in instances:
            print(f'  Line {inst["line"]}: func={inst["func"]}, allow_duplicate={inst["allow_dup"]}')
        print()

if conflict_count == 0:
    print("No unresolved duplicate output conflicts found.")
else:
    print(f"Found {conflict_count} CONFLICT(s) that need fixing!")

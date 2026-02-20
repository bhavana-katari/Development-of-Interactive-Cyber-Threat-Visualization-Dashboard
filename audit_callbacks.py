import re
from collections import defaultdict

def find_duplicates(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()

    # Even more robust regex
    # Matches Output( ... ) where ... contains two quoted strings
    # and optional other stuff. 
    # This avoids backreference issues if there are multiple quotes on the line.
    
    # 1. Broadly find all Output calls
    output_pattern = r'Output\s*\((.*?)\)'
    
    outputs = defaultdict(list)
    matches = list(re.finditer(output_pattern, content, re.DOTALL))
    print(f"Total Output declarations found: {len(matches)}")

    for match in matches:
        inner = match.group(1).strip()
        # Find all strings in the call
        strings = re.findall(r'[\'"](.*?)[\'"]', inner)
        
        if len(strings) >= 2:
            oid = strings[0]
            oprop = strings[1]
            has_allow_dup = 'allow_duplicate' in inner and 'True' in inner
            
            line_no = content.count('\n', 0, match.start()) + 1
            
            outputs[(oid, oprop)].append({
                'line': line_no,
                'allow_duplicate': has_allow_dup,
                'full_text': match.group(0).replace('\n', ' ')
            })
        else:
            # Maybe it's Output(component_id='...', component_property='...')
            pass

    print(f"--- Audit results for {filename} ---")
    conflict_found = False
    for (oid, oprop), instances in outputs.items():
        if len(instances) > 1:
            no_dup = [inst for inst in instances if not inst['allow_duplicate']]
            if len(no_dup) > 0:
                print(f"CONFLICT: ID: {oid}, Property: {oprop}")
                for inst in instances:
                    print(f"  - Line {inst['line']}: {inst['full_text']} (allow_duplicate={inst['allow_duplicate']})")
                conflict_found = True
            else:
                print(f"NOTE: Duplicate ID: {oid}, Property: {oprop} (Correctly managed at lines {[i['line'] for i in instances]})")
    
    if not conflict_found:
        print("No critical duplicate callback output conflicts detected.")

if __name__ == "__main__":
    find_duplicates('app.py')

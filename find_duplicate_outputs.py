import re
import collections

def find_duplicates(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Match Output(id='id', component_property='prop' ...) or Output('id', 'prop' ...)
    output_pattern = re.compile(r'Output\s*\(\s*(?:id=)?[\'"](?P<id>.*?)[\'"]\s*,\s*(?:component_property=)?[\'"](?P<prop>.*?)[\'"]', re.DOTALL)
    
    outputs = []
    for match in output_pattern.finditer(content):
        # Find line number
        line_no = content.count('\n', 0, match.start()) + 1
        outputs.append((match.group('id'), match.group('prop'), line_no, match.group(0)))
    
    print(f"Total Outputs found: {len(outputs)}")
    
    counts = collections.Counter([(o[0], o[1]) for o in outputs])
    duplicates = [item for item, count in counts.items() if count > 1]
    
    if not duplicates:
        print("No duplicate outputs found.")
    else:
        print(f"Found {len(duplicates)} duplicate output(s):")
        lines = content.split('\n')
        for d in duplicates:
            print(f"\nOutput ID: {d[0]}, Property: {d[1]}")
            for o in outputs:
                if (o[0], o[1]) == d:
                    line_text = lines[o[2]-1]
                    has_ad = 'allow_duplicate=True' in line_text or 'allow_duplicate=True' in o[3]
                    print(f"  Line {o[2]}: {line_text.strip()} (allow_duplicate: {has_ad})")

if __name__ == "__main__":
    find_duplicates(r'c:\Users\KUSUMA\Desktop\cyber-threat-dashboard-infosys\app.py')

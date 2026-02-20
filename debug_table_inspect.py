from app import render_threat_history_table

res = render_threat_history_table(0, None, 1)
# res is a Div([table, footer])
print('Type:', type(res))
children = res.children
print('Children count:', len(children))
if len(children) > 0:
    table = children[0]
    print('Table type:', type(table))
    try:
        tbody = table.children[0]
        rows = tbody.children
        print('Rows:', len(rows))
        if len(rows) > 1:
            first = rows[1]
            print('First row cell values:')
            for c in first.children:
                print(' -', repr(c.children))
    except Exception as e:
        print('Error inspecting table structure:', e)

footer = children[1] if len(children) > 1 else None
print('Footer:', footer)

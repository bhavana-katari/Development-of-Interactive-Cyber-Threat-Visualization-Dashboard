from app import analyze_threat_history, get_combined_history

print('Running analyze_threat_history test...')
raw = get_combined_history(limit=50)
out = analyze_threat_history(1, raw, '')
print('Returned type:', type(out))
if out is None:
    print('No output (None)')
else:
    print('Output produced (card or alert).')

from app import get_combined_history
import pandas as pd

print("Testing Analyze History callback logic...")

# Get data for analysis
data = get_combined_history(limit=100)
print(f"Total records for analysis: {len(data)}")

if not data:
    print("ERROR: No data available!")
    exit(1)

# Convert to DataFrame
df = pd.DataFrame(data)

print(f"\nDataFrame shape: {df.shape}")
print(f"DataFrame columns: {list(df.columns)}")

# Ensure all required columns exist
for col in ["severity", "type", "status", "country", "source_ip"]:
    if col not in df.columns:
        df[col] = "Unknown"
        print(f"WARNING: Missing column '{col}', added with default values")

# Calculate statistics
total = len(df)
unique_sources = df["source_ip"].nunique()
severity_counts = df["severity"].value_counts()
type_counts = df["type"].value_counts()
country_counts = df["country"].value_counts().head(8)
status_counts = df["status"].value_counts()

print(f"\n--- CHART 1: Severity Distribution ---")
print(f"Total threats: {total}")
print(f"Severity breakdown:")
for sev, count in severity_counts.items():
    print(f"  {sev}: {count}")

print(f"\n--- CHART 2: Threat Type Distribution (Top 8) ---")
for typ, count in type_counts.head(8).items():
    print(f"  {typ}: {count}")

print(f"\n--- CHART 3: Top Attack Sources by Country ---")
for country, count in country_counts.items():
    print(f"  {country}: {count}")

print(f"\n--- CHART 4: Threat Status Distribution ---")
for status, count in status_counts.items():
    print(f"  {status}: {count}")

print(f"\n--- SUMMARY STATISTICS ---")
print(f"Total Threats: {total}")
print(f"Unique Sources: {unique_sources}")
print(f"Most Common Type: {type_counts.index[0] if len(type_counts) > 0 else 'N/A'}")
print(f"Top Country: {country_counts.index[0] if len(country_counts) > 0 else 'N/A'}")

print(f"\n✓ All analytics data is available and ready for charting!")

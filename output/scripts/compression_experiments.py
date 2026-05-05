import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the experimental data
# Ensure your CSV file is named 'experiment_log.csv' or change the name below
df = pd.read_csv('../CSV/sequential/experiment_log.csv')

# --- 1. Stacked Bar Chart (Total Proving Time) ---
# We group by children_count and calculate the mean for each component
df_mean = df.groupby('children_count')[['pure_proving_duration', 'compression_duration']].mean().reset_index()

plt.figure(figsize=(10, 6))
plt.bar(df_mean['children_count'], df_mean['pure_proving_duration'], 
        label='Pure Proving Duration', color='#3498db', alpha=0.8)
plt.bar(df_mean['children_count'], df_mean['compression_duration'], 
        bottom=df_mean['pure_proving_duration'], label='Compression Duration', color='#e74c3c', alpha=0.8)

plt.xlabel('Children Count (Complexity)')
plt.ylabel('Duration (ms)')
plt.title('Impact of Batch Size on Proving & Compression Time')
plt.legend()
plt.grid(axis='y', linestyle='--', alpha=0.6)
plt.savefig('stacked_duration_chart.png')

# --- 2. Line Chart with Distribution (Proof Size Tendency) ---
plt.figure(figsize=(10, 6))
# Using seaborn's lineplot to automatically show the mean and confidence interval (shaded area)
# This effectively shows the 'tendency' and variance for multiple entries per count
sns.lineplot(data=df, x='children_count', y='receipt_size_kb', 
             marker='o', color='#2ecc71', label='Receipt Size (KB)')

plt.xlabel('Children Count')
plt.ylabel('Proof Size (KB)')
plt.title('Proof Size Tendency vs. Project Scale')
plt.grid(True, linestyle='--', alpha=0.6)
plt.savefig('proof_size_line_chart.png')

print("Charts successfully generated.")
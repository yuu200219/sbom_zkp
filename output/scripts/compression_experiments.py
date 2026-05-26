# 1. batch size (max children_count) vs. proving time (pure_proving_duration + compression_duration)
# 2. batch size (max children_count) vs. proof size (receipt_size_kb)

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

script_dir = os.path.dirname(os.path.abspath(__file__))
csv_files = [
    # os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=15/flask_3.1.3_experiment_log.csv'),
    # os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=50/semantic_kernel_1.14.2_experiment_log.csv'),
    # os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=15/semantic_kernel_1.14.2_experiment_log.csv'),
    # os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=15/react_experiment_log.csv')
]
output_dir = os.path.join(script_dir, '../png')

def compression_experiment():
    df_list = []

    for file_path in csv_files:
        if os.path.exists(file_path):
            try:
                temp_df = pd.read_csv(file_path)
                # 增加 'project' 欄位以便區分（取檔名的一部分作為標記）
                project_name = os.path.basename(file_path).split('_')[0]
                temp_df['project'] = project_name
                df_list.append(temp_df)
                print(f"Successfully loaded: {file_path}")
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
        else:
            print(f"Warning: File not found at {file_path}")

    if not df_list:
        print("No data loaded, skipping plotting.")
        return
        
    df = pd.concat(df_list, ignore_index=True)
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
    save_path = os.path.join(output_dir, 'children_count_compression.png')
    plt.savefig(save_path)
    

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
    save_path = os.path.join(output_dir, 'proof_size_line_chart.png')
    plt.savefig(save_path)

    print("Charts successfully generated.")

if __name__ == "__main__":
    compression_experiment()
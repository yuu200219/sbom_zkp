import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILES = [
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/semantic-kernel_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/nemo_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/express_experiment_log.csv'),
    # os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/serverless_experiment_log.csv'), 
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/flask_experiment_log.csv')
]
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '../../../png/recursive/benchmark/')
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data():
    dfs = []
    for csv_file in CSV_FILES:
        if not os.path.exists(csv_file):
            continue
        try:
            temp_df = pd.read_csv(csv_file)
            temp_df['source'] = os.path.basename(csv_file).replace('_experiment_log.csv', '')
            dfs.append(temp_df)
        except Exception as e:
            pass
    if not dfs: return None
    df = pd.concat(dfs, ignore_index=True)
    df['overhead_cycles'] = df['total_cycles'] - df['user_cycles']
    return df

def main():
    df = load_data()
    if df is None: return
    
    # Ignore descendant count > 50
    df = df[df['descendants_count'] <= 50]
    
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})
    
    df_agg = df.groupby('descendants_count').agg({
        'receipt_size_kb': 'mean',
        'seal_size_kb': 'mean'
    }).reset_index()
    
    fig, ax1 = plt.subplots(figsize=(12, 7))
    
    # Scatter plot for receipt size
    sns.scatterplot(data=df, x='descendants_count', y='receipt_size_kb', hue='source', palette='viridis', alpha=0.7, ax=ax1)
    
    # Line plot for receipt size average
    sns.lineplot(data=df_agg, x='descendants_count', y='receipt_size_kb', color='crimson', marker='^', markersize=8, linewidth=2.5, label='Avg Receipt Size', ax=ax1)
    
    # Line plot for seal size average (optional, but good for size context)
    sns.lineplot(data=df_agg, x='descendants_count', y='seal_size_kb', color='darkorange', marker='s', markersize=7, linewidth=2.0, linestyle='--', label='Avg Seal Size', ax=ax1)
    
    ax1.set_title("Receipt Size vs Descendants Count")
    ax1.set_xlabel("Descendants Count")
    ax1.set_ylabel("Size (KB)", color='black')
    
    ax1.legend(loc='upper left', bbox_to_anchor=(1.05, 1))
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'receipt_size_vs_descendants_count.png'), dpi=300, bbox_inches='tight')
    print("Saved receipt_size_vs_descendants_count.png")

if __name__ == '__main__':
    main()
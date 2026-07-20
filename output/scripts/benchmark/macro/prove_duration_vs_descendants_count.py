import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILES = [
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/semantic-kernel_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/nemo_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/express_experiment_log.csv'),
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
    
    if 'compression_duration' in df.columns:
        df['total_prove_duration'] = (df['pure_prove_duration'] + df['compression_duration'].fillna(0)) / 60000
    else:
        df['total_prove_duration'] = df['pure_prove_duration'] / 60000
        
    return df

def main():
    df = load_data()
    if df is None: return
    
    df = df[df['descendants_count'] < 50]
    
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})
    
    df_agg = df.groupby('descendants_count').agg({
        'total_prove_duration': 'mean',
        'receipt_size_kb': 'mean'
    }).reset_index()
    
    fig, ax1 = plt.subplots(figsize=(12, 7))
    sns.scatterplot(data=df, x='descendants_count', y='total_prove_duration', hue='source', palette='viridis', alpha=0.7, ax=ax1)
    sns.lineplot(data=df_agg, x='descendants_count', y='total_prove_duration', color='darkcyan', marker='o', linewidth=2.5, label='Avg Proving Duration', ax=ax1)
    
    ax1.set_title("Proving Duration vs Descendants Count")
    ax1.set_xlabel("Descendants Count")
    ax1.set_ylabel("Proving Duration (min)", color='darkcyan')
    ax1.tick_params(axis='y', labelcolor='darkcyan')
    
    ax2 = ax1.twinx()
    sns.lineplot(data=df_agg, x='descendants_count', y='receipt_size_kb', marker='^', markersize=8, color='crimson', linewidth=2.0, linestyle='--', ax=ax2, label='Avg Receipt Size')
    sns.scatterplot(data=df, x='descendants_count', y='receipt_size_kb', color="crimson", alpha=0.3, ax=ax2, legend=False)
    
    ax2.set_ylabel("Size (KB)", color='black')
    ax2.tick_params(axis='y', labelcolor='black')
    ax2.grid(False)
    
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', bbox_to_anchor=(1.05, 1))
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'prove_duration_vs_descendants_count.png'), dpi=300, bbox_inches='tight')
    print("Saved prove_duration_vs_descendants_count.png")

if __name__ == '__main__':
    main()

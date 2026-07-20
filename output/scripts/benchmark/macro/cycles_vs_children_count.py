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
    return df

def main():
    df = load_data()
    if df is None: return
    df = df[df['children_count'] < 50]
    
    
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})
    
    df_agg = df.groupby('children_count').agg({
        'user_cycles': 'mean',
        'total_cycles': 'mean',
        'overhead_cycles': 'mean',
        'receipt_size_kb': 'mean'
    }).reset_index()
    
    fig, ax1 = plt.subplots(figsize=(12, 7))
    
    # Stacked bar chart for user_cycles and overhead_cycles
    ax1.bar(df_agg['children_count'], df_agg['user_cycles'], color='indigo', alpha=0.8, label='Avg User Cycles')
    ax1.bar(df_agg['children_count'], df_agg['overhead_cycles'], bottom=df_agg['user_cycles'], color='deeppink', alpha=0.8, label='Avg Overhead Cycles')
    
    ax1.set_title("Cycles vs Children Count")
    ax1.set_xlabel("Children Count")
    ax1.set_ylabel("Cycles", color='indigo')
    ax1.tick_params(axis='y', labelcolor='indigo')
    ax1.ticklabel_format(style='plain', axis='y')
    
    ax2 = ax1.twinx()
    sns.lineplot(data=df_agg, x='children_count', y='receipt_size_kb', marker='^', markersize=8, color='crimson', linewidth=2.0, linestyle='--', ax=ax2, label='Avg Receipt Size')
    sns.scatterplot(data=df, x='children_count', y='receipt_size_kb', color="crimson", alpha=0.3, ax=ax2, legend=False)
    
    ax2.set_ylabel("Size (KB)", color='black')
    ax2.tick_params(axis='y', labelcolor='black')
    ax2.grid(False)
    
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', bbox_to_anchor=(1.05, 1))
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'cycles_vs_children_count.png'), dpi=300, bbox_inches='tight')
    print("Saved cycles_vs_children_count.png")

if __name__ == '__main__':
    main()

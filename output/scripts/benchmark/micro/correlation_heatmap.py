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
    sns.set_theme(style="white")
    cols = ['pure_prove_duration', 'receipt_size_kb', 'total_cycles', 'user_cycles', 'overhead_cycles', 'segments', 'depth', 'children_count', 'descendants_count', 'guest_io_read', 'guest_dependency_check', 'guest_severity_check', 'guest_merkle_io_read', 'guest_merkle_check']
    corr = df[cols].corr()
    plt.figure(figsize=(14, 12))
    sns.heatmap(corr, annot=True, cmap='coolwarm', fmt=".2f", vmin=-1, vmax=1)
    plt.title("Correlation Heatmap of Proof Metrics")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'correlation_heatmap.png'), dpi=300)
    print("Saved correlation_heatmap.png")

if __name__ == '__main__':
    main()

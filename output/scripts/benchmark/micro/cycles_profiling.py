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
    sns.set_theme(style="whitegrid")
    
    for x_axis in ['children_count', 'descendants_count']:
        df_agg = df.groupby(x_axis).agg({
            'guest_io_read': 'mean',
            'guest_dependency_check': 'mean',
            'guest_severity_check': 'mean',
            'guest_merkle_io_read': 'mean',
            'guest_merkle_check': 'mean'
        }).reset_index()
        
        df_agg.set_index(x_axis).plot(kind='bar', stacked=True, figsize=(12, 7), colormap='Set2')
        plt.title(f"Cycle Profiling vs {x_axis.replace('_', ' ').title()}")
        plt.xlabel(x_axis.replace('_', ' ').title())
        plt.ylabel("Cycles")
        plt.legend(title="Guest Operations", bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, f'cycle_profiling_{x_axis}.png'), dpi=300)
        print(f"Saved cycle_profiling_{x_axis}.png")

if __name__ == '__main__':
    main()

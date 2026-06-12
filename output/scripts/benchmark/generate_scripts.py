import os

MACRO_DIR = "/home/yuu200219/Documents/Projects/sbom_zkp/output/scripts/benchmark/macro"
MICRO_DIR = "/home/yuu200219/Documents/Projects/sbom_zkp/output/scripts/benchmark/micro"

COMMON_HEADER = """import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILES = [
    os.path.join(SCRIPT_DIR, '../../../../CSV/recursive/never_seen/semantic-kernel_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../../CSV/recursive/never_seen/nemo_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../../CSV/recursive/never_seen/express_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../../CSV/recursive/never_seen/serverless_experiment_log.csv'), 
    os.path.join(SCRIPT_DIR, '../../../../CSV/recursive/never_seen/flask_experiment_log.csv')
]
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '../../../../png/recursive/benchmark/')
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
"""

PROVE_DURATION_TEMPLATE = """
def main():
    df = load_data()
    if df is None: return
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})
    
    df_agg = df.groupby('{x_axis}').agg({'pure_prove_duration': 'mean'}).reset_index()
    
    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x='{x_axis}', y='pure_prove_duration', hue='source', palette='viridis', alpha=0.7)
    sns.lineplot(data=df_agg, x='{x_axis}', y='pure_prove_duration', color='darkcyan', marker='o', linewidth=2.5, label='Avg Proving Duration')
    
    plt.title("Proving Duration vs {title_x}")
    plt.xlabel("{title_x}")
    plt.ylabel("Proving Duration (ms)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'prove_duration_vs_{x_axis}.png'), dpi=300)
    print("Saved prove_duration_vs_{x_axis}.png")

if __name__ == '__main__':
    main()
"""

CYCLES_TEMPLATE = """
def main():
    df = load_data()
    if df is None: return
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})
    
    df_agg = df.groupby('{x_axis}').agg({
        'user_cycles': 'mean',
        'total_cycles': 'mean',
        'overhead_cycles': 'mean'
    }).reset_index()
    
    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x='{x_axis}', y='total_cycles', hue='source', palette='viridis', alpha=0.3, legend=False)
    
    sns.lineplot(data=df_agg, x='{x_axis}', y='total_cycles', color='darkviolet', marker='o', linewidth=2.5, label='Avg Total Cycles')
    sns.lineplot(data=df_agg, x='{x_axis}', y='user_cycles', color='indigo', marker='s', linewidth=2.5, label='Avg User Cycles')
    sns.lineplot(data=df_agg, x='{x_axis}', y='overhead_cycles', color='deeppink', marker='d', linewidth=2.5, label='Avg Overhead Cycles')
    
    plt.title("Cycles vs {title_x}")
    plt.xlabel("{title_x}")
    plt.ylabel("Cycles")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'cycles_vs_{x_axis}.png'), dpi=300)
    print("Saved cycles_vs_{x_axis}.png")

if __name__ == '__main__':
    main()
"""

for x_axis, title_x in [("children_count", "Children Count"), ("depth", "Depth"), ("descendants_count", "Descendants Count")]:
    with open(os.path.join(MACRO_DIR, f"prove_duration_vs_{x_axis}.py"), "w") as f:
        f.write(COMMON_HEADER + PROVE_DURATION_TEMPLATE.replace("{x_axis}", x_axis).replace("{title_x}", title_x))
    with open(os.path.join(MACRO_DIR, f"cycles_vs_{x_axis}.py"), "w") as f:
        f.write(COMMON_HEADER + CYCLES_TEMPLATE.replace("{x_axis}", x_axis).replace("{title_x}", title_x))

HEATMAP = """
def main():
    df = load_data()
    if df is None: return
    sns.set_theme(style="white")
    cols = ['pure_prove_duration', 'receipt_size_kb', 'total_cycles', 'user_cycles', 'segments', 'depth', 'children_count', 'descendants_count', 'guest_io_read', 'guest_dependency_check', 'guest_severity_check', 'guest_merkle_io_read', 'guest_merkle_check']
    corr = df[cols].corr()
    plt.figure(figsize=(14, 12))
    sns.heatmap(corr, annot=True, cmap='coolwarm', fmt=".2f", vmin=-1, vmax=1)
    plt.title("Correlation Heatmap of Proof Metrics")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'correlation_heatmap.png'), dpi=300)
    print("Saved correlation_heatmap.png")

if __name__ == '__main__':
    main()
"""

PROFILING = """
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
"""

with open(os.path.join(MICRO_DIR, "correlation_heatmap.py"), "w") as f:
    f.write(COMMON_HEADER + HEATMAP)
with open(os.path.join(MICRO_DIR, "cycles_profiling.py"), "w") as f:
    f.write(COMMON_HEADER + PROFILING)


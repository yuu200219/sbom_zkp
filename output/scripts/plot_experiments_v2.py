import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# 1. CONFIGURATION & PATHS
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILES = [
    os.path.join(SCRIPT_DIR, '../CSV/recursive/never_seen/semantic-kernel_experiment_log.csv'),
    # os.path.join(SCRIPT_DIR, '../CSV/recursive/never_seen/nemo_experiment_log.csv'),
    # os.path.join(SCRIPT_DIR, '../CSV/recursive/never_seen/express_experiment_log.csv'),
    # os.path.join(SCRIPT_DIR, '../CSV/recursive/never_seen/serverless_experiment_log.csv'), 
    # os.path.join(SCRIPT_DIR, '../CSV/recursive/never_seen/flask_experiment_log.csv')
]
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '../png/recursive/semantic-kernel/')

os.makedirs(OUTPUT_DIR, exist_ok=True)

def plot_proving_v2():
    dfs = []
    for csv_file in CSV_FILES:
        if not os.path.exists(csv_file):
            print(f"Warning: CSV file not found at {csv_file}")
            continue
        try:
            temp_df = pd.read_csv(csv_file)
            # Add a source column to distinguish between files if needed
            temp_df['source'] = os.path.basename(csv_file).replace('_with_cid.csv', '').replace('_experiment_log.csv', '')
            dfs.append(temp_df)
            print(f"Loaded {len(temp_df)} rows from {csv_file}")
        except Exception as e:
            print(f"Error reading {csv_file}: {e}")

    if not dfs:
        print("Error: No data loaded. Exiting.")
        return

    df = pd.concat(dfs, ignore_index=True)

    # ==========================================
    # DATA PREPARATION
    # ==========================================
    # 計算額外開銷/填充週期 (Overhead / Padding Cycles)
    df['overhead_cycles'] = df['total_cycles'] - df['user_cycles']

    # General styling
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})

    # Group by children_count for the trend line
    df_agg = df.groupby('children_count').agg({
        'pure_prove_duration': 'mean',
        'user_cycles': 'mean',
        'total_cycles': 'mean',
        'overhead_cycles': 'mean', # <--- 新增這裡
        'receipt_size_kb': 'mean',
        'seal_size_kb': 'mean' 
    }).reset_index()

    # ----------------------------------------------------
    # GRAPH 1: Proving Duration & Sizes vs Children Count
    # ----------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(12, 7))
    
    # Plot Duration on ax1
    sns.lineplot(data=df_agg, x='children_count', y='pure_prove_duration', 
                 marker='o', markersize=8, color='darkcyan', linewidth=2.5, linestyle='--', ax=ax1, label='Global Avg Proving Duration')
    sns.scatterplot(data=df, x='children_count', y='pure_prove_duration', 
                    hue='source', ax=ax1, palette='viridis')
    
    ax1.set_title("Proving Duration & Sizes vs Children Count (Combined)", pad=15, fontweight='bold')
    ax1.set_xlabel("Children Count (Branching Factor)")
    ax1.set_ylabel("Proving Duration (ms)", color='darkcyan')
    ax1.tick_params(axis='y', labelcolor='darkcyan')
    ax1.grid(True, linestyle='--', alpha=0.6)

    # Secondary Axis: Sizes (Receipt & Seal)
    ax2 = ax1.twinx()
    
    # Plot Receipt Size
    sns.lineplot(data=df_agg, x='children_count', y='receipt_size_kb', 
                 marker='^', markersize=8, color='crimson', linewidth=2.0, linestyle='--', ax=ax2, label='Avg Receipt Size')
    sns.scatterplot(data=df, x='children_count', y='receipt_size_kb', 
                    color="crimson", alpha=0.3, ax=ax2, legend=False)
                    
    # Plot Seal Size
    sns.lineplot(data=df_agg, x='children_count', y='seal_size_kb', 
                 marker='s', markersize=7, color='darkorange', linewidth=2.0, linestyle=':', ax=ax2, label='Avg Seal Size')
    sns.scatterplot(data=df, x='children_count', y='seal_size_kb', 
                    color="darkorange", alpha=0.3, ax=ax2, legend=False)
    
    ax2.set_ylabel("Size (KB)", color='black') 
    ax2.tick_params(axis='y', labelcolor='black')
    ax2.grid(False) 

    # Legends 
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', bbox_to_anchor=(1.05, 1))

    plt.tight_layout()
    duration_out_path = os.path.join(OUTPUT_DIR, "01_duration_and_sizes_vs_children.png")
    plt.savefig(duration_out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[Success] Proving Duration & Sizes graph saved to: {duration_out_path}")

    # ----------------------------------------------------
    # GRAPH 2: zkVM Cycles & Sizes vs Children Count
    # ----------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(12, 7))
    
    # 1. Plot Total Cycles
    sns.lineplot(data=df_agg, x='children_count', y='total_cycles', 
                 marker='o', markersize=8, color='darkviolet', linewidth=2.5, linestyle='-', ax=ax1, label='Avg Total Cycles')
    
    # 2. Plot User Cycles
    sns.lineplot(data=df_agg, x='children_count', y='user_cycles', 
                 marker='o', markersize=8, color='indigo', linewidth=2.5, linestyle='--', ax=ax1, label='Avg User Cycles')
    sns.scatterplot(data=df, x='children_count', y='user_cycles', 
                    color='indigo', alpha=0.3, ax=ax1, legend=False)

    # 3. Plot Overhead/Padding Cycles (Total - User)
    sns.lineplot(data=df_agg, x='children_count', y='overhead_cycles', 
                 marker='d', markersize=8, color='deeppink', linewidth=2.5, linestyle=':', ax=ax1, label='Avg Overhead (Total - User)')
    sns.scatterplot(data=df, x='children_count', y='overhead_cycles', 
                    color='deeppink', alpha=0.3, ax=ax1, legend=False)
    
    ax1.set_title("zkVM Cycles & Sizes vs Children Count (Combined)", pad=15, fontweight='bold')
    ax1.set_xlabel("Children Count (Branching Factor)")
    ax1.set_ylabel("Cycles Counts", color='indigo')
    ax1.tick_params(axis='y', labelcolor='indigo')
    ax1.ticklabel_format(style='plain', axis='y') 
    ax1.grid(True, linestyle='--', alpha=0.6)

    # Secondary Axis: Sizes (Receipt & Seal)
    ax2 = ax1.twinx()
    
    # Plot Receipt Size
    sns.lineplot(data=df_agg, x='children_count', y='receipt_size_kb', 
                 marker='^', markersize=8, color='crimson', linewidth=2.0, linestyle='--', ax=ax2, label='Avg Receipt Size')
    sns.scatterplot(data=df, x='children_count', y='receipt_size_kb', 
                    color="crimson", alpha=0.3, ax=ax2, legend=False)
                    
    # Plot Seal Size 
    sns.lineplot(data=df_agg, x='children_count', y='seal_size_kb', 
                 marker='s', markersize=7, color='darkorange', linewidth=2.0, linestyle=':', ax=ax2, label='Avg Seal Size')
    sns.scatterplot(data=df, x='children_count', y='seal_size_kb', 
                    color="darkorange", alpha=0.3, ax=ax2, legend=False)
    
    ax2.set_ylabel("Size (KB)", color='black')
    ax2.tick_params(axis='y', labelcolor='black')
    ax2.grid(False)

    # Legends 
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', bbox_to_anchor=(1.05, 1))

    plt.tight_layout()
    cycles_out_path = os.path.join(OUTPUT_DIR, "02_cycles_and_sizes_vs_children.png")
    plt.savefig(cycles_out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[Success] Cycles & Sizes graph saved to: {cycles_out_path}")

if __name__ == "__main__":
    plot_proving_v2()
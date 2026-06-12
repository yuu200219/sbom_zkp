import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.optimize import curve_fit

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Experiment logs contain descendants_count, Verification logs contain verify_duration
EXP_CSV_FILES = [
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/semantic-kernel_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/nemo_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/express_experiment_log.csv'),
    # os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/serverless_experiment_log.csv'), 
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/flask_experiment_log.csv')
]

VERIFY_CSV_FILES = [
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/verification/semantic-kernel_verification_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/verification/nemo_verification_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/verification/express_verification_log.csv'),
    # os.path.join(SCRIPT_DIR, '../../../CSV/recursive/verification/serverless_verification_log.csv'), 
    os.path.join(SCRIPT_DIR, '../../../CSV/recursive/verification/flask_verification_log.csv')
]

OUTPUT_DIR = os.path.join(SCRIPT_DIR, '../../../png/recursive/benchmark/')
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data():
    exp_dfs = []
    for csv_file in EXP_CSV_FILES:
        if os.path.exists(csv_file):
            try:
                temp_df = pd.read_csv(csv_file)
                temp_df['source'] = os.path.basename(csv_file).replace('_experiment_log.csv', '')
                exp_dfs.append(temp_df)
            except Exception: pass
            
    ver_dfs = []
    for csv_file in VERIFY_CSV_FILES:
        if os.path.exists(csv_file):
            try:
                temp_df = pd.read_csv(csv_file)
                temp_df['source'] = os.path.basename(csv_file).replace('_verification_log.csv', '')
                ver_dfs.append(temp_df)
            except Exception: pass
            
    if not exp_dfs or not ver_dfs: return None
    exp_df = pd.concat(exp_dfs, ignore_index=True)
    ver_df = pd.concat(ver_dfs, ignore_index=True)
    
    # Use comp_name to merge descendants_count into verification dataframe if missing
    if 'descendants_count' not in ver_df.columns:
        if 'comp_name' in ver_df.columns and 'comp_name' in exp_df.columns:
            # deduplicate by comp_name
            exp_subset = exp_df[['comp_name', 'descendants_count']].drop_duplicates(subset=['comp_name'])
            ver_df = ver_df.merge(exp_subset, on='comp_name', how='left')
    
    return ver_df

def log2_sq_model(x, a, b):
    # Model: y = a * (log2(x + 1))^2 + b
    return a * (np.log2(x + 1)**2) + b

def linear_model(x, a, b):
    # Model: y = a * x + b
    return a * x + b

def main():
    df = load_data()
    if df is None: return
    
    
    
    # drop nas just in case
    df = df.dropna(subset=['depth', 'verify_duration'])
    
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})
    
    df_agg = df.groupby('depth').agg({
        'verify_duration': ['mean', 'std'],
        'receipt_size_kb': 'mean'
    }).reset_index()
    
    df_agg.columns = ['depth', 'mean_verify_duration', 'std_verify_duration', 'mean_receipt_size']
    
    fig, ax1 = plt.subplots(figsize=(12, 7))
    sns.scatterplot(data=df, x='depth', y='verify_duration', hue='source', palette='viridis', alpha=0.3, ax=ax1, legend=False)
    
    # Plot Mean and Std
    ax1.errorbar(df_agg['depth'], df_agg['mean_verify_duration'], yerr=df_agg['std_verify_duration'], 
                 fmt='o', color='red', capsize=5, label='Avg Verification Duration ± Std Dev')
    
    
    
    ax1.set_title("Verification Duration vs Depth")
    ax1.set_xlabel("Depth")
    ax1.set_ylabel("Verification Duration (ms)", color='red')
    ax1.tick_params(axis='y', labelcolor='red')
    
    # Secondary Axis for Receipt Size
    ax2 = ax1.twinx()
    sns.lineplot(data=df_agg, x='depth', y='mean_receipt_size', marker='^', markersize=8, color='crimson', linewidth=2.0, linestyle='--', ax=ax2, label='Avg Receipt Size')
    
    ax2.set_ylabel("Size (KB)", color='black')
    ax2.tick_params(axis='y', labelcolor='black')
    ax2.grid(False)
    
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', bbox_to_anchor=(1.05, 1))
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'verify_duration_vs_depth.png'), dpi=300, bbox_inches='tight')
    print("Saved verify_duration_vs_depth.png")

if __name__ == '__main__':
    main()

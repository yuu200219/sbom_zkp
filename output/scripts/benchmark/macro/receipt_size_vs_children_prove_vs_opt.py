# help me compare the opt prove duration and prover.prove prove duration
# prover.prove log is in the ../../../CSV/recursive/never_seen, prover_with_opts log is in the ../../../CSV/recursive_opt/never_seen

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 定義要讀取的實驗組件名稱
COMP_NAMES = ['express', 'flask', 'nemo', 'semantic-kernel']

# prover.prove 產生的舊版遞迴日誌 (recursive)
CSV_FILES_PROVE = [
    os.path.join(SCRIPT_DIR, f'../../../CSV/recursive/never_seen/{name}_experiment_log.csv')
    for name in COMP_NAMES
]

# prover_with_opts 產生的新版優化遞迴日誌 (recursive_opt)
CSV_FILES_OPT = [
    os.path.join(SCRIPT_DIR, f'../../../CSV/recursive_opt/never_seen/{name}_experiment_log.csv')
    for name in COMP_NAMES
]

# 輸出 PNG 資料夾路徑
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '../../../png/recursive_opt/benchmark/')
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_data(file_list):
    dfs = []
    for csv_file in file_list:
        if not os.path.exists(csv_file):
            continue
        try:
            temp_df = pd.read_csv(csv_file)
            temp_df['source'] = os.path.basename(csv_file).replace('_experiment_log.csv', '')
            dfs.append(temp_df)
        except Exception as e:
            pass
    if not dfs: 
        return None
    df = pd.concat(dfs, ignore_index=True)
    
    # 計算 End-to-End 證明時間 = 純證明時間 + 壓縮證明時間
    if 'compression_duration' in df.columns:
        df['total_prove_duration'] = df['pure_prove_duration'] + df['compression_duration'].fillna(0)
    else:
        df['total_prove_duration'] = df['pure_prove_duration']
        
    return df

def main():
    # 載入兩組不同的資料集
    df_prove = load_data(CSV_FILES_PROVE)
    df_opt = load_data(CSV_FILES_OPT)
    
    if df_prove is None or df_opt is None:
        print("Error: 找不到對比所需的 CSV 實驗數據檔案。")
        return
        
    # 過濾 children_count <= 50
    df_prove = df_prove[df_prove['children_count'] < 50]
    df_opt = df_opt[df_opt['children_count'] < 50]
    
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})
    
    # 依 children_count 進行平均聚合
    df_prove_agg = df_prove.groupby('children_count').agg({
        'receipt_size_kb': 'mean'
    }).reset_index()
    
    df_opt_agg = df_opt.groupby('children_count').agg({
        'receipt_size_kb': 'mean'
    }).reset_index()
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # 1. 繪製 prover.prove 的數據
    sns.lineplot(
        data=df_prove_agg, x='children_count', y='receipt_size_kb', 
        marker='o', markersize=8, color='#3498db', linewidth=2.5, linestyle=':', 
        ax=ax, label='Avg Receipt Size (prover.prove)'
    )
    sns.scatterplot(
        data=df_prove, x='children_count', y='receipt_size_kb', 
        color='#3498db', alpha=0.3, ax=ax, legend=False
    )
    
    # 2. 繪製 prover_with_opts 的數據
    sns.lineplot(
        data=df_opt_agg, x='children_count', y='receipt_size_kb', 
        marker='s', markersize=8, color='#e74c3c', linewidth=2.5, linestyle='--', 
        ax=ax, label='Avg Receipt Size (prover_with_opts)'
    )
    sns.scatterplot(
        data=df_opt, x='children_count', y='receipt_size_kb', 
        color='#e74c3c', alpha=0.3, ax=ax, legend=False
    )
    
    ax.set_title("Receipt Size Comparison: prover.prove vs. prover_with_opts", pad=15, fontweight='bold')
    ax.set_xlabel("Children Count")
    ax.set_ylabel("Total Receipt Size (kb)")
    ax.grid(True, linestyle='--', alpha=0.6)
    
    plt.legend(loc='upper left')
    plt.tight_layout()
    
    output_path = os.path.join(OUTPUT_DIR, 'receipt_size_kb_vs_children_count_prove_vs_opt.png')
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved receipt size comparison graph to: {output_path}")

if __name__ == '__main__':
    main()


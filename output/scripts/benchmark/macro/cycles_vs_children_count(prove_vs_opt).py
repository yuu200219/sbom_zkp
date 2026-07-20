# help me write the code, you can reference the code style from cycles_opt_vs_children_count.py.
# Originally, at cycles_opt_vs_children_count.py, there is only one receipt size, which is the use the prover.prove.
# I want to add another receipt size line, which is produce by prover_with_opts.
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
    df['overhead_cycles'] = df['total_cycles'] - df['user_cycles']
    return df

def main():
    # 載入兩組不同的資料集
    df_prove = load_data(CSV_FILES_PROVE)
    df_opt = load_data(CSV_FILES_OPT)
    df_prove = df_prove[df_prove['children_count'] < 50]
    df_opt = df_opt[df_opt['children_count'] < 50]
    
    if df_prove is None or df_opt is None:
        print("Error: 找不到對比所需的 CSV 實驗數據檔案。")
        return
    
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})
    
    # 依 children_count 進行平均聚合
    df_prove_agg = df_prove.groupby('children_count').agg({
        'receipt_size_kb': 'mean'
    }).reset_index()
    
    df_opt_agg = df_opt.groupby('children_count').agg({
        'user_cycles': 'mean',
        'total_cycles': 'mean',
        'overhead_cycles': 'mean',
        'receipt_size_kb': 'mean'
    }).reset_index()
    
    fig, ax1 = plt.subplots(figsize=(12, 7))
    
    # 1. 在左 y 軸 (ax1) 繪製優化版 (opt) 的週期 (Cycles) 堆疊長條圖
    ax1.bar(df_opt_agg['children_count'], df_opt_agg['user_cycles'], color='indigo', alpha=0.8, label='Avg User Cycles')
    ax1.bar(df_opt_agg['children_count'], df_opt_agg['overhead_cycles'], bottom=df_opt_agg['user_cycles'], color='deeppink', alpha=0.8, label='Avg Overhead Cycles')
    
    ax1.set_title("Cycles vs Children Count (prove vs opt)")
    ax1.set_xlabel("Children Count")
    ax1.set_ylabel("Cycles", color='indigo')
    ax1.tick_params(axis='y', labelcolor='indigo')
    ax1.ticklabel_format(style='plain', axis='y')
    
    # 2. 建立右 y 軸 (ax2) 以繪製兩種證明的收據大小 (Receipt Size)
    ax2 = ax1.twinx()
    
    # 繪製舊版 prover.prove 的收據曲線與散佈點
    sns.lineplot(data=df_prove_agg, x='children_count', y='receipt_size_kb', marker='o', markersize=8, color='#00AA00', linewidth=2.0, linestyle=':', ax=ax2, label='Avg Receipt Size (prover.prove)')
    sns.scatterplot(data=df_prove, x='children_count', y='receipt_size_kb', color="#00AA00", alpha=0.2, ax=ax2, legend=False)
    
    # 繪製新版 prover_with_opts 的收據曲線與散佈點
    sns.lineplot(data=df_opt_agg, x='children_count', y='receipt_size_kb', marker='^', markersize=8, color='crimson', linewidth=2.0, linestyle='--', ax=ax2, label='Avg Receipt Size (prover_with_opts)')
    sns.scatterplot(data=df_opt, x='children_count', y='receipt_size_kb', color="crimson", alpha=0.2, ax=ax2, legend=False)
    
    ax2.set_ylabel("Size (KB)", color='black')
    ax2.tick_params(axis='y', labelcolor='black')
    ax2.grid(False)
    
    # 3. 合併左、右兩軸的圖例 (Legend)
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', bbox_to_anchor=(1.05, 1))
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'cycles_vs_children_count_prove_vs_opt.png'), dpi=300, bbox_inches='tight')
    print("Saved cycles_vs_children_count_prove_vs_opt.png")

if __name__ == '__main__':
    main()
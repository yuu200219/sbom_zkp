import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from scipy.optimize import curve_fit

# ==========================================
# 1. CONFIGURATION & PATHS
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILES = [
    os.path.join(SCRIPT_DIR, '../CSV/recursive/verification/express_verification_log.csv'),
    os.path.join(SCRIPT_DIR, '../CSV/recursive/verification/serverless_verification_log.csv'),
    os.path.join(SCRIPT_DIR, '../CSV/recursive/verification/semantic-kernel_verification_log.csv'),
    os.path.join(SCRIPT_DIR, '../CSV/recursive/verification/flask_verification_log.csv')
]
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '../png/recursive/combined/')   

os.makedirs(OUTPUT_DIR, exist_ok=True)

def log2_sq_model(x, a, b):
    # Model: y = a * (log2(x + 1))^2 + b
    return a * (np.log2(x + 1)**2) + b

def plot_verification_analysis():
    dfs = []
    for csv_file in CSV_FILES:
        if not os.path.exists(csv_file):
            print(f"Warning: CSV file not found at {csv_file}")
            continue
        try:
            temp_df = pd.read_csv(csv_file)
            if 'verify_duration' not in temp_df.columns:
                print(f"Warning: 'verify_duration' not found in {csv_file}. Skipping.")
                continue
            temp_df['source'] = os.path.basename(csv_file).replace('_with_cid.csv', '').replace('_experiment_log.csv', '')
            dfs.append(temp_df)
            print(f"Loaded {len(temp_df)} rows from {csv_file}")
        except Exception as e:
            print(f"Error reading {csv_file}: {e}")

    if not dfs:
        print("Error: No data with 'verify_duration' loaded. Exiting.")
        return

    df = pd.concat(dfs, ignore_index=True)

    # 學術圖表風格設置：使用 white 背景以避免雙 Y 軸的網格線重疊混亂
    sns.set_theme(style="ticks")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})

    # ==========================================
    # 2. DATA AGGREGATION (加入 receipt_size_kb)
    # ==========================================
    # 在這裡同時計算 verify_duration 和 receipt_size_kb 的平均值
    df_agg = df.groupby('children_count').agg({
        'verify_duration': ['mean', 'std', 'count'],
        'receipt_size_kb': ['mean', 'std']  # 新增計算 receipt_size_kb
    }).reset_index()
    
    # 重新命名欄位以便後續調用
    df_agg.columns = [
        'children_count', 
        'mean_verify_duration', 'std_verify_duration', 'count',
        'mean_receipt_size', 'std_receipt_size'
    ]

    # Aggregate by depth (保留你原本的 Graph 2 資料)
    df_depth_agg = df.groupby('depth').agg({
        'receipt_size_kb': ['mean', 'std', 'count']
    }).reset_index()
    df_depth_agg.columns = ['depth', 'mean_receipt_size', 'std_receipt_size', 'count']

    # ----------------------------------------------------
    # GRAPH 1: Verify Duration & Receipt Size vs Children Count
    # ----------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(10, 6))
    
    # [Data 1]: Individual Measurements (散佈圖)
    # sns.scatterplot(data=df, x='children_count', y='verify_duration', 
    #                 alpha=0.3, color='gray', label='Individual Measurements', ax=ax1)
    sns.lineplot(
        data=df, 
        x='children_count', 
        y='verify_duration', 
        ax=ax1,                # 關鍵：告訴 Seaborn 畫在右邊的 Y 軸上
        marker='o', 
        color='red', 
        linestyle='-',        # 保留點劃線風格以區分左軸的實線/虛線
        label='Verification Duration (ms)'
        # errorbar=None        # (選項) 如果你不想要 Seaborn 自動產生的淡色陰影區間，可以取消註解這行
    )
    
    # [Data 2]: Mean Verify Duration (均值與誤差棒)
    ax1.errorbar(df_agg['children_count'], df_agg['mean_verify_duration'], 
                 yerr=df_agg['std_verify_duration'], fmt='o', alpha=0.5, color='red', 
                 capsize=5, label='Mean Verify Duration ± Std Dev')

    # [Data 3]: Curve Fitting O(log^2 n)
    try:
        if len(df_agg) >= 2:
            x_data = df_agg['children_count'].values
            y_data = df_agg['mean_verify_duration'].values
            
            popt, _ = curve_fit(log2_sq_model, x_data, y_data)
            x_fit = np.linspace(min(x_data), max(x_data), 100)
            y_fit = log2_sq_model(x_fit, *popt)
            
            ax1.plot(x_fit, y_fit, '--', color='gray', linewidth=2, 
                     label=fr'Fit: $O(\log^2(n))$ ($y = {popt[0]:.2f} \cdot \log_2(n+1)^2 + {popt[1]:.2f}$)')
    except Exception as e:
        print(f"Could not fit O(log^2 n) curve: {e}")

    # 設置左側 Y 軸 (ax1) 的標籤與顏色
    ax1.set_xlabel("Children Count (Branching Factor)")
    ax1.set_ylabel("Verification Duration (ms)", color='black')
    ax1.tick_params(axis='y', labelcolor='black')
    ax1.grid(True, linestyle='--', alpha=0.6)

    # --- 建立第二個 Y 軸 (ax2) ---
    ax2 = ax1.twinx()
    
    # [Data 4]: Average Receipt Size (折線圖，使用不同的標記與顏色區分)
    sns.lineplot(
        data=df, 
        x='children_count', 
        y='receipt_size_kb', 
        ax=ax2,                # 關鍵：告訴 Seaborn 畫在右邊的 Y 軸上
        marker='o', 
        color='orange', 
        linestyle='-',        # 保留點劃線風格以區分左軸的實線/虛線
        label='Receipt Size (KB)'
        # errorbar=None        # (選項) 如果你不想要 Seaborn 自動產生的淡色陰影區間，可以取消註解這行
    )
    # ax2.errorbar(df_agg['children_count'], df_agg['mean_receipt_size'], 
    #              yerr=df_agg['std_receipt_size'], fmt='o', alpha=0.5, color='orange',
    #              capsize=5, label='Mean Receipt Size ± Std Dev')
    
    
    # 設置右側 Y 軸 (ax2) 的標籤與顏色
    ax2.set_ylabel("Receipt Size (KB)", color='black')
    ax2.tick_params(axis='y', labelcolor='black')
    ax2.grid(False) # 關閉 ax2 的網格避免畫面過於混亂

    # --- 合併 ax1 與 ax2 的圖例 (Legend) ---
    lines_1, labels_1 = ax1.get_legend_handles_labels()
    lines_2, labels_2 = ax2.get_legend_handles_labels()
    ax1.legend(lines_1 + lines_2, labels_1 + labels_2, loc='upper left', framealpha=0.9)

    plt.title("Verification Duration and Receipt Size vs Branching Factor", pad=15)
    plt.tight_layout()
    
    save_path = os.path.join(OUTPUT_DIR, "verification_duration_and_size_vs_children.png")
    plt.savefig(save_path, dpi=300)
    plt.close()
    print(f"[Success] Combined verification analysis graph saved to: {save_path}")

    # ----------------------------------------------------
    # GRAPH 2: Receipt Size vs Depth (保持不變)
    # ----------------------------------------------------
    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x='depth', y='receipt_size_kb', alpha=0.4, color='gray', label='Individual Measurements')
    plt.errorbar(df_depth_agg['depth'], df_depth_agg['mean_receipt_size'], yerr=df_depth_agg['std_receipt_size'], fmt='o', color='green', capsize=5, label='Mean ± Std Dev')
    plt.title("Receipt Size vs Depth", pad=15)
    plt.xlabel("Tree Depth")
    plt.ylabel("Receipt Size (KB)")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    save_path_size = os.path.join(OUTPUT_DIR, "receipt_size_vs_depth.png")
    plt.savefig(save_path_size, dpi=300)
    plt.close()
    print(f"[Success] Receipt size analysis graph saved to: {save_path_size}")

if __name__ == "__main__":
    plot_verification_analysis()

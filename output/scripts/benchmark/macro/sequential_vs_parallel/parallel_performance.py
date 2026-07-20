import pandas as pd
import os
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

CSV_RECURSIVE_FILES = [
    os.path.join(SCRIPT_DIR, '../../../../CSV/recursive_opt/never_seen/express_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../../CSV/recursive_opt/never_seen/flask_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../../CSV/recursive_opt/never_seen/nemo_experiment_log.csv'),
    os.path.join(SCRIPT_DIR, '../../../../CSV/recursive_opt/never_seen/semantic-kernel_experiment_log.csv'),
]

CSV_PARALLEL_FILES = [
    os.path.join(SCRIPT_DIR, '../../../../CSV/parallel_opt/never_seen/express_experiment_log.csv'), # NOTE: Changed to parallel_opt
    os.path.join(SCRIPT_DIR, '../../../../CSV/parallel_opt/never_seen/flask_experiment_log.csv'),    # NOTE: Changed to parallel_opt
    os.path.join(SCRIPT_DIR, '../../../../CSV/parallel_opt/never_seen/nemo_experiment_log.csv'),     # NOTE: Changed to parallel_opt
    os.path.join(SCRIPT_DIR, '../../../../CSV/parallel_opt/never_seen/semantic-kernel_experiment_log.csv'),# NOTE: Changed to parallel_opt
]

def load_and_process_logs(file_paths):
    all_data = []
    for f_path in file_paths:
        try:
            df = pd.read_csv(f_path)
            project_name = os.path.basename(f_path).split('_experiment_log.csv')[0].replace('-', ' ').title()
            # Convert pure_prove_duration from milliseconds to minutes
            df['duration_minutes'] = df['pure_prove_duration'] / (1000 * 60)
            df['project_name'] = project_name
            all_data.append(df)

        except FileNotFoundError:
            print(f"File not found: {f_path}")
            continue

        except Exception as e:
            print(f"Error processing {f_path}: {e}")
            continue


    if not all_data:
        return pd.DataFrame()
    
    combined_df = pd.concat(all_data)

    # Aggregate data per project: sum durations and average children_count
    aggregated_df = combined_df.groupby('project_name').agg(
        total_duration=('duration_minutes', 'sum'),
        avg_children_count=('children_count', 'mean')
    ).reset_index()
    return aggregated_df

# Load and process data
recursive_df = load_and_process_logs(CSV_RECURSIVE_FILES)
parallel_df = load_and_process_logs(CSV_PARALLEL_FILES)

# Merge dataframes and calculate speedup
if not recursive_df.empty and not parallel_df.empty:

    merged_df = pd.merge(recursive_df, parallel_df, on='project_name', suffixes=('_recursive', '_parallel'))
    merged_df['speedup'] = merged_df['total_duration_recursive'] / merged_df['total_duration_parallel']

    # Sort by avg_children_count
    merged_df = merged_df.sort_values(by='avg_children_count_recursive', ascending=True) # Using recursive's children count for sorting
    projects = merged_df['project_name'].tolist()
    seq_times = merged_df['total_duration_recursive'].tolist()
    par_times = merged_df['total_duration_parallel'].tolist()
    speedups = merged_df['speedup'].tolist()
    children_counts = merged_df['avg_children_count_recursive'].tolist() # To be used in x-axis label

    print("Processed Data:")
    print(merged_df)
    print("\nSorted and Merged DataFrame:")
    print(merged_df)

else:
    print("Error: Could not load data for comparison.")
    projects = []
    seq_times = []
    par_times = []
    speedups = []
    children_counts = []

# ==========================================
# 1. 學術圖表全域風格設定
# ==========================================

sns.set_theme(style="whitegrid")
plt.rcParams.update({
    'font.size': 12, 
    'axes.labelsize': 13, 
    'axes.titlesize': 14,
    'legend.fontsize': 11
})

# ==========================================
# 2. 實驗數據輸入 (已從 hh:mm:ss 轉換為 Minutes)
# ==========================================

x = np.arange(len(projects))
width = 0.35  # 柱狀圖寬度

# ==========================================
# 3. 繪圖引擎啟動
# ==========================================
fig, ax1 = plt.subplots(figsize=(11, 7))

# --- 左 Y 軸：端到端證明時間 (長條圖) ---
# zorder=3 確保長條圖壓在底層網格線之上
rects1 = ax1.bar(x - width/2, seq_times, width, label='Sequential (Baseline)', color='steelblue', alpha=0.85, zorder=3)
rects2 = ax1.bar(x + width/2, par_times, width, label='Task-Parallel (Ours)', color='darkorange', alpha=0.85, zorder=3)

ax1.set_xlabel('Open Source Projects (Sorted by Average Children Count)', fontweight='bold')
ax1.set_ylabel('End-to-End Proving Latency (Minutes)', fontweight='bold')
ax1.set_title('Performance Optimization: Task-Parallel Orchestration on 32-Core zkVM', fontweight='bold', pad=20)
ax1.set_xticks(x)
ax1.set_xticklabels([f"{p} ({c:.0f})" for p, c in zip(projects, children_counts)], rotation=45, ha='right')

# 設定背景網格 (zorder=0 讓網格在最底層)
ax1.grid(axis='y', linestyle='--', alpha=0.7, zorder=0)

# 動態設定左側 Y 軸的上限，多留 20% 空間，避免長條圖頂到折線圖
max_time = max(max(seq_times), max(par_times)) if seq_times and par_times else 1
ax1.set_ylim(0, max_time * 1.25) 

# --- 右 Y 軸：系統加速比 (折線圖) ---
ax2 = ax1.twinx()

# 🎯 繪製折線圖 (zorder=5 確保折線圖畫在長條圖的最上層)
line1 = ax2.plot(x, speedups, color='crimson', marker='D', markersize=8, 
                 linestyle='-', linewidth=2.5, label='Speedup Factor', zorder=5)

ax2.set_ylabel('Speedup Factor (x)', color='crimson', fontweight='bold')
ax2.tick_params(axis='y', labelcolor='crimson')

# 動態設定右側 Y 軸的範圍，保留足夠的上方空間給「數值文字」
min_speedup = min(speedups) if speedups else 1.0
max_speedup = max(speedups) if speedups else 1.6
ax2.set_ylim(max(1.0, min_speedup - 0.2), max_speedup + 0.3) 
ax2.grid(False) # 關閉右側網格避免畫面雜亂

# --- 🎯 標註具體加速比數值在折線圖點上 ---
for i, v in enumerate(speedups):
    # 使用 bbox 加入半透明白色背景，確保文字不會跟長條圖或網格線糊在一起
    ax2.text(i, v + 0.05, f"{v:.2f}x", color='crimson', 
             ha='center', va='bottom', fontweight='bold', fontsize=11, zorder=6,
             bbox=dict(facecolor='white', edgecolor='none', alpha=0.7, pad=1.5))

# --- 合併雙軸圖例 ---
bars_handles, bars_labels = ax1.get_legend_handles_labels()
line_handles, line_labels = ax2.get_legend_handles_labels()
# 將圖例放在左上角，並加上微透明背景
ax1.legend(bars_handles + line_handles, bars_labels + line_labels, loc='upper left', framealpha=0.9)
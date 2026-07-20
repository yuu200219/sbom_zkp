import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.dates as mdates
import matplotlib.ticker as mticker
import os

def plot_cpu_usage(csv_path, output_path):
    """
    Analyzes CPU usage from a CSV file and generates a plot.
    """
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"File not found: {csv_path}")
        return

    # Stop processing if there are 60 consecutive rows with no tasks
    consecutive_empty_count = 0
    stop_index = -1
    for i, tasks_str in enumerate(df['Running_Tasks']):
        if str(tasks_str).strip() == '[]' or pd.isna(tasks_str):
            consecutive_empty_count += 1
        else:
            consecutive_empty_count = 0
        
        if consecutive_empty_count >= 60:
            stop_index = i - 59 
            break

    if stop_index != -1:
        df = df.iloc[:stop_index]

    if df.empty:
        print(f"No data to plot for {csv_path} after filtering. Skipping.")
        return

    # Convert Timestamp to datetime objects and calculate elapsed time in seconds
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    start_timestamp = df['Timestamp'].iloc[0]
    df['ElapsedSeconds'] = (df['Timestamp'] - start_timestamp).dt.total_seconds()
    
    # 取得確切的總花費時間
    total_time_seconds = df['ElapsedSeconds'].iloc[-1]

    # Calculate average CPU usage
    core_cols = [f'Core_{i}' for i in range(32)]
    df['avg_cpu'] = df[core_cols].mean(axis=1)

    # 重新定義狀態判斷邏輯：區分 Proving, Lock, 與 Other
    def get_task_state(tasks_str):
        tasks_str = str(tasks_str).strip()
        if tasks_str == '[]' or not tasks_str:
            return 'other'
        
        tasks_str_cleaned = tasks_str.strip('[]')
        if not tasks_str_cleaned:
            return 'other'
            
        tasks = [task.strip().lower() for task in tasks_str_cleaned.split(',')]
        
        if not tasks:
            return 'other'
            
        # 優先檢查是否有卡在 Lock (字串包含 lock 或 waiting)
        # 你可以根據你實際 log 輸出的 "waiting lock" 字眼進行微調
        if any('lock' in task or 'waiting' in task for task in tasks):
            return 'waiting_lock'
            
        proving_tasks = [task for task in tasks if task.startswith('proving:')]
        
        # 如果有 Proving 任務，我們就視為在 Proving 階段 (不一定要過半，避免剛啟動時被誤判)
        if len(proving_tasks) > 0:
            return 'proving'
            
        return 'other'

    df['task_state'] = df['Running_Tasks'].apply(get_task_state)

    # Plotting
    fig, ax = plt.subplots(figsize=(15, 7))

    # Plot average CPU usage
    window_size = 30  # 每 30 筆資料平均一次 (如果圖還是太密，可以調高到 60 或 120)
    df['smoothed_cpu'] = df['avg_cpu'].rolling(window=window_size, min_periods=1).mean()
    ax.plot(df['ElapsedSeconds'], df['smoothed_cpu'], label='Average CPU Usage', color='mediumblue', linewidth=1.5, zorder=5)

    # 定義狀態對應的顏色
    state_colors = {
        'proving': 'orange',          # 正常運算中
        'waiting_lock': 'lightcoral', # 卡在 Lock 效能瓶頸 (淺紅色)
        'other': 'lightyellow'        # 其他或閒置 (淺黃色)
    }

    start_seconds = None
    current_state = None

    plot_df = df[['ElapsedSeconds', 'task_state']].copy()

    for i, row in plot_df.iterrows():
        state = row['task_state']
        
        if start_seconds is None:
            start_seconds = row['ElapsedSeconds']
            current_state = state

        if state != current_state:
            ax.axvspan(start_seconds, row['ElapsedSeconds'], facecolor=state_colors[current_state], alpha=0.4, zorder=1)
            start_seconds = row['ElapsedSeconds']
            current_state = state
    
    # Add the last span
    if start_seconds is not None:
         ax.axvspan(start_seconds, df['ElapsedSeconds'].iloc[-1], facecolor=state_colors[current_state], alpha=0.4, zorder=1)

    # Formatting the plot
    ax.set_title(f'Average CPU Usage Over Time ({os.path.basename(csv_path)})', fontsize=14)
    ax.set_xlabel('Execution Time (hr:mm:ss)', fontsize=12)
    ax.set_ylabel('Average CPU Usage (%)', fontsize=12)
    ax.set_ylim(0, 100)
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)

    # Format x-axis to show hr:mm:ss
    def format_seconds(seconds, pos=None):
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds_rem = int(seconds % 60)
        return f'{hours:02d}:{minutes:02d}:{seconds_rem:02d}'
    
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(format_seconds))
    
    # 建立自訂圖例 (Legend) 來解釋背景顏色
    from matplotlib.patches import Patch
    legend_elements = [
        plt.Line2D([0], [0], color='blue', lw=2, label='Average CPU Usage'),
        Patch(facecolor='orange', alpha=0.4, label='Proving Active'),
        Patch(facecolor='lightcoral', alpha=0.4, label='Waiting Lock (Bottleneck)'),
        Patch(facecolor='lightyellow', alpha=0.4, label='Other / Idle')
    ]
    ax.legend(handles=legend_elements, loc='lower left', framealpha=1.0)

    # 在圖表右下角加上總執行時間的浮水印/文字方塊
    formatted_total_time = format_seconds(total_time_seconds)
    text_box_props = dict(boxstyle='round,pad=0.5', facecolor='white', alpha=0.8, edgecolor='gray')
    ax.text(0.98, 0.05, f'Total Execution Time: {formatted_total_time}', 
            transform=ax.transAxes, fontsize=12, fontweight='bold', color='darkred',
            verticalalignment='bottom', horizontalalignment='right', bbox=text_box_props, zorder=10)

    fig.autofmt_xdate()
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    
    # 同時也在 Terminal 印出總時間
    print(f"[{os.path.basename(csv_path)}] Plot saved to {output_path}")
    print(f"[{os.path.basename(csv_path)}] Total Execution Time: {formatted_total_time}\n")
    print(f"[{os.path.basename(csv_path)}] Overall Avg CPU Usage: {df['avg_cpu'].mean():.1f}%\n")


if __name__ == '__main__':
    # File paths are relative to the script location
    recursive_csv = '../../../CSV/recursive_opt/express_cpu_monitor.csv'
    parallel_csv = '../../../CSV/parallel_opt/express_cpu_monitor.csv'
    
    # Output paths for plots
    recursive_plot_output = '../../../png/recursive_opt/express_cpu_usage.png'
    parallel_plot_output = '../../../png/parallel_opt/express_cpu_usage.png'

    plot_cpu_usage(recursive_csv, recursive_plot_output)
    plot_cpu_usage(parallel_csv, parallel_plot_output)
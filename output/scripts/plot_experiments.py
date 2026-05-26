import pandas as pd
import matplotlib.pyplot as plt
import os
import re

# 1. 定義 CSV 檔案列表
script_dir = os.path.dirname(os.path.abspath(__file__))
csv_files = [
    # os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=15/flask_3.1.3_old_experiment_log.csv'),
    os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=50/flask_3.1.3_old_experiment_log.csv'), 
    os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=15/flask_3.1.3_old_experiment_log.csv')
    # os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=15/react_experiment_log.csv'),
]
output_dir = os.path.join(script_dir, '../png/recursive/flask_3.1.3/')

def plot_experiments():
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    df_list = []
    
    # 2. 迴圈讀取所有檔案並標記來源
    for file_path in csv_files:
        if os.path.exists(file_path):
            try:
                temp_df = pd.read_csv(file_path)
                # 增加 'project' 欄位以便區分（取檔名的一部分作為標記）
                # project_name = os.path.basename(file_path).split('_')[0]
                
                batch_info = re.search(r'batch_size=\d+', file_path)
                label_name = batch_info.group(0) if batch_info else "Unknown Batch"
                
                # temp_df['project'] = project_name
                temp_df['project'] = label_name
                
                df_list.append(temp_df)
                print(f"Successfully loaded: {file_path}")
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
        else:
            print(f"Warning: File not found at {file_path}")

    if not df_list:
        print("No data loaded, skipping plotting.")
        return

    # 3. 合併所有 DataFrames
    df = pd.concat(df_list, ignore_index=True)

    plots = [
        ('cycle', 'depth'),
        ('pure_proving_duration', 'depth'),
        ('cycle', 'children_count'),
        ('pure_proving_duration', 'children_count'),
        ('cycle', 'receipt_size_kb'),
        ('cycle', 'seal_size_kb'),
        ('pure_proving_duration', 'receipt_size_kb'),
        ('pure_proving_duration', 'seal_size_kb'),
        ('pure_proving_duration', 'cycle'),
        ('children_count', 'receipt_size_kb') 
    ]

    for x, y in plots:
        if x not in df.columns or y not in df.columns:
            print(f"Skipping plot ({x}, {y}): Column(s) missing.")
            continue

        plt.figure(figsize=(12, 7))
        
        # 4. 使用不同顏色區分專案 (Optional but recommended)
        for project in df['project'].unique():
            proj_df = df[df['project'] == project]
            plt.scatter(proj_df[x], proj_df[y], alpha=0.6, label=project)
        
        plt.title(f'{y} vs {x} (Combined Projects)')
        plt.xlabel(x)
        plt.ylabel(y)
        plt.legend() # 顯示專案標籤
        plt.grid(True, linestyle='--', alpha=0.7)
        
        filename = f'{y}_{x}_combined.png'.replace('/', '_')
        save_path = os.path.join(output_dir, filename)
        plt.savefig(save_path)
        
        plt.close()
        print(f"Saved combined plot: {save_path}")

if __name__ == "__main__":
    plot_experiments()
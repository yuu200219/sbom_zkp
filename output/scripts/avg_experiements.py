import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# 1. Define CSV file list
script_dir = os.path.dirname(os.path.abspath(__file__))
csv_files = [
    # os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=15/flask_3.1.3_old_experiment_log.csv'),
    os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=50/semantic_kernel_1.14.2_experiment_log.csv'),
    # os.path.join(script_dir, '../CSV/sequential/never_seen/batch_size=15/react_experiment_log.csv')
]
output_dir = os.path.join(script_dir, '../png')

def plot_avg_experiments():
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    df_list = []
    
    # 2. Load all files and mark source
    for file_path in csv_files:
        if os.path.exists(file_path):
            try:
                temp_df = pd.read_csv(file_path)
                project_name = os.path.basename(file_path).split('_')[0]
                temp_df['project'] = project_name
                df_list.append(temp_df)
                print(f"Successfully loaded: {file_path}")
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
        else:
            print(f"Warning: File not found at {file_path}")

    if not df_list:
        print("No data loaded, skipping plotting.")
        return

    # 3. Combine DataFrames
    df = pd.concat(df_list, ignore_index=True)

    # 4. Average cycle/time per depth
    metrics = ['cycle', 'pure_proving_duration']
    group_bys = ['depth', 'children_count']

    for group_by in group_bys:
        for metric in metrics:
            plt.figure(figsize=(10, 6))
            
            # Using barplot to show averages with error bars
            sns.barplot(data=df, x=group_by, y=metric, color='skyblue', legend=False)
            
            plt.title(f'Average {metric.replace("_", " ").title()} per {group_by.replace("_", " ").title()}')
            plt.xlabel(group_by.replace("_", " ").title())
            plt.ylabel(f'Average {metric.replace("_", " ").title()}')
            plt.grid(axis='y', linestyle='--', alpha=0.7)
            
            filename = f'avg_{metric}_per_{group_by}.png'
            save_path = os.path.join(output_dir, filename)
            plt.savefig(save_path)
            plt.close()
            print(f"Saved average plot: {save_path}")

if __name__ == "__main__":
    plot_avg_experiments()

import os
import glob
import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Define paths (請依照你實際的路徑結構調整)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REC_UPDATE_DIR = os.path.join(SCRIPT_DIR, '../../../../CSV/recursive_opt/update')
PAR_UPDATE_DIR = os.path.join(SCRIPT_DIR, '../../../../CSV/parallel_opt/update')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '.')

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_directory_data(dir_path, category_name):
    """通用函數：讀取資料夾下所有的 CSV 並標記對應的實驗類別"""
    if not os.path.exists(dir_path):
        print(f"Warning: Directory not found: {dir_path}")
        return pd.DataFrame(), pd.DataFrame()
    
    csv_pattern = os.path.join(dir_path, "*.csv")
    csv_files = glob.glob(csv_pattern)
    
    node_dfs = []
    path_summary_data = []
    
    for f in csv_files:
        try:
            df = pd.read_csv(f)
            if df.empty:
                continue
            
            # 處理欄位名稱可能不一致的問題 (pure_prove_duration vs pure_proving_duration)
            prove_col = 'pure_proving_duration'
            if 'pure_prove_duration' in df.columns:
                prove_col = 'pure_prove_duration'
            elif 'pure_proving_time' in df.columns:
                prove_col = 'pure_proving_time'
            
            # Node-level details
            df_nodes = df[['depth', 'children_count', prove_col]].copy()
            df_nodes.rename(columns={prove_col: 'pure_proving_time'}, inplace=True)
            df_nodes['category'] = category_name
            df_nodes['pure_proving_time_sec'] = df_nodes['pure_proving_time'] / 1000.0
            node_dfs.append(df_nodes)
            
            # Path-level details (計算該次 update 的總耗時)
            filename = os.path.basename(f)
            depth_match = re.search(r'dep(\d+)', filename)
            
            if depth_match:
                update_depth = int(depth_match.group(1))
            elif "side-channel" in filename:
                update_depth = 4 # Known default fallback depth for side-channel
            else:
                update_depth = df['depth'].max()
                
            total_time_ms = df[prove_col].sum()
            total_time_sec = total_time_ms / 1000.0
            
            path_summary_data.append({
                'update_depth': update_depth,
                'total_time_sec': total_time_sec,
                'category': category_name,
                'file_name': filename
            })
        except Exception as e:
            print(f"Error parsing {f}: {e}")
            
    if not node_dfs:
        return pd.DataFrame(), pd.DataFrame()
        
    df_nodes_all = pd.concat(node_dfs, ignore_index=True)
    df_path_summary = pd.DataFrame(path_summary_data)
    
    return df_nodes_all, df_path_summary

def main():
    print("Loading data...")
    # 1. Load Datasets from both directories
    df_rec_nodes, df_rec_summary = load_directory_data(REC_UPDATE_DIR, 'Recursive Opt Update')
    df_par_nodes, df_par_summary = load_directory_data(PAR_UPDATE_DIR, 'Parallel Opt Update')
    
    if df_rec_nodes.empty and df_par_nodes.empty:
        print("Error: Could not load any datasets. Please check file paths.")
        return
    
    # Combine data for comparison
    df_nodes_combined = pd.concat([df_rec_nodes, df_par_nodes], ignore_index=True)
    df_summary_combined = pd.concat([df_rec_summary, df_par_summary], ignore_index=True)
    
    # 2. Setup styles
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({
        'font.size': 11,
        'axes.labelsize': 12,
        'axes.titlesize': 14,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'figure.titlesize': 16
    })
    
    # --- PLOT 1: Node Proving Time vs Depth ---
    # plt.figure(figsize=(10, 6))
    # sns.scatterplot(
    #     data=df_nodes_combined, 
    #     x='depth', 
    #     y='pure_proving_time_sec', 
    #     hue='category', 
    #     style='category',
    #     palette='Set1', 
    #     alpha=0.7,
    #     s=80
    # )
    # # Add simple trend lines using aggregate means
    # df_agg = df_nodes_combined.groupby(['depth', 'category'])['pure_proving_time_sec'].mean().reset_index()
    # sns.lineplot(
    #     data=df_agg, 
    #     x='depth', 
    #     y='pure_proving_time_sec', 
    #     hue='category', 
    #     legend=False, 
    #     palette='Set1', 
    #     linewidth=2, 
    #     linestyle='--'
    # )
    
    # plt.title("Node Proving Duration vs Depth (Recursive vs Parallel)")
    # plt.xlabel("Node Depth")
    # plt.ylabel("Proving Duration (seconds)")
    # plt.legend(title="Optimization Strategy")
    # plt.tight_layout()
    # output_plot1 = os.path.join(OUTPUT_DIR, 'opt_compare_vs_depth.png')
    # plt.savefig(output_plot1, dpi=300)
    # print(f"Saved Plot 1: {output_plot1}")
    # plt.close()
    
    # # --- PLOT 2: Node Proving Time vs Children Count ---
    # plt.figure(figsize=(10, 6))
    # sns.scatterplot(
    #     data=df_nodes_combined, 
    #     x='children_count', 
    #     y='pure_proving_time_sec', 
    #     hue='category', 
    #     style='category',
    #     palette='Set1', 
    #     alpha=0.7,
    #     s=80
    # )
    # # Add regression / trend lines
    # sns.lineplot(
    #     data=df_nodes_combined.groupby(['children_count', 'category'])['pure_proving_time_sec'].mean().reset_index(),
    #     x='children_count',
    #     y='pure_proving_time_sec',
    #     hue='category',
    #     legend=False,
    #     palette='Set1',
    #     linewidth=2
    # )
    
    # plt.title("Node Proving Duration vs Children Count (Recursive vs Parallel)")
    # plt.xlabel("Children Count (Number of Dependencies)")
    # plt.ylabel("Proving Duration (seconds)")
    # plt.legend(title="Optimization Strategy")
    # plt.tight_layout()
    # output_plot2 = os.path.join(OUTPUT_DIR, 'opt_compare_vs_children.png')
    # plt.savefig(output_plot2, dpi=300)
    # print(f"Saved Plot 2: {output_plot2}")
    # plt.close()
    
    # --- PLOT 3: Total Proof Overhead Comparison (Recursive vs Parallel) ---
    if not df_summary_combined.empty:
        plt.figure(figsize=(10, 6))
        
        # Sort summary by update depth to ensure lines are drawn logically
        df_summary_sorted = df_summary_combined.sort_values(by='update_depth')
        
        # Plot total times for both strategies
        sns.scatterplot(
            data=df_summary_sorted, 
            x='update_depth', 
            y='total_time_sec',
            hue='category',
            style='category',
            palette='Set1',
            s=120, 
            zorder=5
        )
        sns.lineplot(
            data=df_summary_sorted, 
            x='update_depth', 
            y='total_time_sec', 
            hue='category',
            palette='Set1',
            linewidth=2, 
            linestyle='-', 
            zorder=4,
            legend=False
        )
        
        plt.title("Total Update Proving Cost: Recursive vs Parallel Optimization")
        plt.xlabel("Updated Package Depth")
        plt.ylabel("Total Proving Time (seconds)")
        plt.xlim(0, df_summary_combined['update_depth'].max() + 1)
        plt.ylim(0, df_summary_combined['total_time_sec'].max() * 1.1) # 10% buffer top
        plt.legend(title="Optimization Strategy")
        plt.tight_layout()
        output_plot3 = os.path.join(OUTPUT_DIR, 'opt_compare_total_time.png')
        plt.savefig(output_plot3, dpi=300)
        print(f"Saved Plot 3: {output_plot3}")
        plt.close()
        
        # Print Text Summary
        print("\n=== Experiment Summary (Total Proving Time per Update Depth) ===")
        pivot_summary = df_summary_sorted.pivot_table(
            index='update_depth', 
            columns='category', 
            values='total_time_sec', 
            aggfunc='mean'
        )
        print(pivot_summary.round(2))

if __name__ == '__main__':
    main()
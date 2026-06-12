# I want to implement the experiments that compare the "first seen package" and "seen package".
# "first seen package" logs  will import from the ../../../CSV/recursive/never_seen/express_experiment_log.csv
# "seen pacakge" logs will import from the ../../../CSV/recursive/update_with_parent_count/
# for each log file in the update_with_parent_count, it record the proving log about the specific depth of update pacakge
# I want to compare the data between the two logs(never seen, update), x axis is the depth/children_count, y axis is the pure_proving_time

import os
import glob
import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Define paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NEVER_SEEN_CSV = os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/express_experiment_log.csv')
UPDATE_DIR = os.path.join(SCRIPT_DIR, '../../../CSV/recursive/update_with_parent_count')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '../../../png/recursive/benchmark/')

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_first_seen_data():
    if not os.path.exists(NEVER_SEEN_CSV):
        print(f"Warning: File not found: {NEVER_SEEN_CSV}")
        return None
    
    df = pd.read_csv(NEVER_SEEN_CSV)
    df = df[['depth', 'children_count', 'pure_prove_duration']].copy()
    df.rename(columns={'pure_prove_duration': 'pure_proving_time'}, inplace=True)
    df['category'] = 'First Seen Package (Never Seen)'
    df['pure_proving_time_sec'] = df['pure_proving_time'] / 1000.0
    return df

def load_seen_data():
    if not os.path.exists(UPDATE_DIR):
        print(f"Warning: Directory not found: {UPDATE_DIR}")
        return None, None
    
    csv_pattern = os.path.join(UPDATE_DIR, "*.csv")
    csv_files = glob.glob(csv_pattern)
    
    node_dfs = []
    path_summary_data = []
    
    for f in csv_files:
        try:
            df = pd.read_csv(f)
            if df.empty:
                continue
            
            # Node-level details
            df_nodes = df[['depth', 'children_count', 'pure_proving_duration']].copy()
            df_nodes.rename(columns={'pure_proving_duration': 'pure_proving_time'}, inplace=True)
            df_nodes['category'] = 'Seen Package (Update)'
            df_nodes['pure_proving_time_sec'] = df_nodes['pure_proving_time'] / 1000.0
            node_dfs.append(df_nodes)
            
            # Path-level details (for the total update experiment comparison)
            filename = os.path.basename(f)
            depth_match = re.search(r'dep(\d+)', filename)
            if depth_match:
                update_depth = int(depth_match.group(1))
            elif "side-channel" in filename:
                update_depth = 4 # Known default fallback depth for side-channel
            else:
                update_depth = df['depth'].max()
                
            total_time_ms = df['pure_proving_duration'].sum()
            total_time_sec = total_time_ms / 1000.0
            
            path_summary_data.append({
                'update_depth': update_depth,
                'total_time_sec': total_time_sec,
                'file_name': filename
            })
        except Exception as e:
            print(f"Error parsing {f}: {e}")
            
    if not node_dfs:
        return None, None
        
    df_nodes_all = pd.concat(node_dfs, ignore_index=True)
    df_path_summary = pd.DataFrame(path_summary_data)
    
    return df_nodes_all, df_path_summary

def main():
    # 1. Load Datasets
    df_first_seen = load_first_seen_data()
    df_seen_nodes, df_path_summary = load_seen_data()
    
    if df_first_seen is None or df_seen_nodes is None:
        print("Error: Could not load required datasets. Please check file paths.")
        return
    
    # Combine node-level data for comparison
    df_nodes_combined = pd.concat([df_first_seen, df_seen_nodes], ignore_index=True)
    
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
    plt.figure(figsize=(10, 6))
    sns.scatterplot(
        data=df_nodes_combined, 
        x='depth', 
        y='pure_proving_time_sec', 
        hue='category', 
        style='category',
        palette='Set1', 
        alpha=0.8,
        s=80
    )
    # Add simple trend lines using aggregate means
    df_agg = df_nodes_combined.groupby(['depth', 'category'])['pure_proving_time_sec'].mean().reset_index()
    sns.lineplot(
        data=df_agg, 
        x='depth', 
        y='pure_proving_time_sec', 
        hue='category', 
        legend=False, 
        palette='Set1', 
        linewidth=2, 
        linestyle='--'
    )
    
    plt.title("Node Proving Duration vs Depth")
    plt.xlabel("Node Depth")
    plt.ylabel("Proving Duration (seconds)")
    plt.legend(title="Experiment Category")
    plt.tight_layout()
    output_plot1 = os.path.join(OUTPUT_DIR, 'update_experiments_vs_depth.png')
    plt.savefig(output_plot1, dpi=300)
    print(f"Saved: {output_plot1}")
    plt.close()
    
    # --- PLOT 2: Node Proving Time vs Children Count ---
    plt.figure(figsize=(10, 6))
    sns.scatterplot(
        data=df_nodes_combined, 
        x='children_count', 
        y='pure_proving_time_sec', 
        hue='category', 
        style='category',
        palette='Set1', 
        alpha=0.8,
        s=80
    )
    # Add regression / trend lines
    sns.lineplot(
        data=df_nodes_combined.groupby(['children_count', 'category'])['pure_proving_time_sec'].mean().reset_index(),
        x='children_count',
        y='pure_proving_time_sec',
        hue='category',
        legend=False,
        palette='Set1',
        linewidth=2
    )
    
    plt.title("Node Proving Duration vs Children Count")
    plt.xlabel("Children Count (Number of Dependencies)")
    plt.ylabel("Proving Duration (seconds)")
    plt.legend(title="Experiment Category")
    plt.tight_layout()
    output_plot2 = os.path.join(OUTPUT_DIR, 'update_experiments_vs_children.png')
    plt.savefig(output_plot2, dpi=300)
    print(f"Saved: {output_plot2}")
    plt.close()
    
    # --- PLOT 3: Total Proof Overhead Comparison (Entire Tree vs Recursive Update Path) ---
    if df_path_summary is not None and not df_path_summary.empty:
        plt.figure(figsize=(10, 6))
        
        # Calculate full tree baseline total duration
        full_tree_total_sec = df_first_seen['pure_proving_time_sec'].sum()
        
        # Plot full tree constant line
        plt.axhline(
            y=full_tree_total_sec, 
            color='crimson', 
            linestyle='-', 
            linewidth=2.5, 
            label=f'Full Tree Proof Baseline ({full_tree_total_sec:.2f}s)'
        )
        
        # Sort path summary by update depth to draw a logical line
        df_path_summary_sorted = df_path_summary.sort_values(by='update_depth')
        
        # Plot recursive update data points
        sns.scatterplot(
            data=df_path_summary_sorted, 
            x='update_depth', 
            y='total_time_sec', 
            color='teal', 
            s=120, 
            zorder=5, 
            label='Recursive Update Path'
        )
        sns.lineplot(
            data=df_path_summary_sorted, 
            x='update_depth', 
            y='total_time_sec', 
            color='teal', 
            linewidth=2, 
            linestyle='-', 
            zorder=4
        )
        
        plt.title("Total Proving Cost: Full SBOM vs Recursive Path Update")
        plt.xlabel("Updated Package Depth")
        plt.ylabel("Total Proving Time (seconds)")
        plt.xlim(0, df_path_summary['update_depth'].max() + 1)
        # Add dynamic buffer to Y-axis limit for better visualization
        plt.ylim(0, max(full_tree_total_sec, df_path_summary['total_time_sec'].max()) * 1.1)
        plt.legend()
        plt.tight_layout()
        output_plot3 = os.path.join(OUTPUT_DIR, 'update_experiments_total_comparison.png')
        plt.savefig(output_plot3, dpi=300)
        print(f"Saved: {output_plot3}")
        plt.close()
        
        print("\n=== Experiment Summary ===")
        print(f"Total Full SBOM Proving Time: {full_tree_total_sec:.2f} seconds ({len(df_first_seen)} packages)")
        print("Recursive Updates:")
        for idx, row in df_path_summary_sorted.iterrows():
            saving_pct = (1.0 - (row['total_time_sec'] / full_tree_total_sec)) * 100.0
            print(f"  - Update at Depth {row['update_depth']}: {row['total_time_sec']:.2f} seconds (Savings: {saving_pct:.1f}%)")

if __name__ == '__main__':
    main()

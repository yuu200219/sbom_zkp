import os
import re
import glob
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# 1. CONFIGURATION & PATHS
# ==========================================
CSV_DIR = "../CSV/recursive/update_with_parent_count/" 
OUTPUT_DIR = "../png/recursive/update_with_parent_count/"

os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_depth_from_filename(filename):
    """
    Extracts the depth digit immediately following 'dep' with any optional separators.
    Matches: dep2_log.csv, (dep3)_log.csv, dep=4.csv, etc.
    """
    match = re.search(r'dep[=_]?(\d+)', filename, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None

def build_summary_dataset(csv_dir):
    """
    Reads each CSV file, calculates the total sum of metrics for that entire run,
    and returns a summarized DataFrame mapping Starting Depth to Whole Update Cost.
    """
    csv_files = glob.glob(os.path.join(csv_dir, "*.csv"))
    if not csv_files:
        print(f"Warning: No CSV files found in directory: {csv_dir}")
        return pd.DataFrame()
    
    summary_rows = []
    
    for file_path in csv_files:
        filename = os.path.basename(file_path)
        depth_val = extract_depth_from_filename(filename)
        
        if depth_val == None:
            print(f"Skipping {filename}: Could not parse 'dep' depth from filename.")
            continue
            
        try:
            df = pd.read_csv(file_path)
            if df.empty:
                print(f"Skipping empty file: {filename}")
                continue
            
            # Dynamic Column Normalization (Handles multiple naming variants)
            time_col = None
            for candidate in ['pure_proving_duration', 'pure_proving_time', 'proving_duration_ms']:
                if candidate in df.columns:
                    time_col = candidate
                    break
                    
            cycle_col = None
            for candidate in ['cycle', 'risczero_cycles_total', 'cycles']:
                if candidate in df.columns:
                    cycle_col = candidate
                    break
            children_col = None
            for candidate in ['children_count', 'children', 'child_count']:
                if candidate in df.columns:
                    children_col = candidate
                    break
                
            parent_col = None
            for candidate in ['parent_count', 'parent', 'parents']:
                if candidate in df.columns:
                    parent_col = candidate
                    break

            if not time_col or not cycle_col:
                print(f"Skipping {filename}: Required duration/cycle headers missing.")
                print(f"Found columns: {list(df.columns)}")
                continue

            # Calculate the cumulative totals for this complete execution
            total_duration = df[time_col].sum()
            total_cycles = df[cycle_col].sum()
            total_packages = len(df) # Useful to observe how many items were re-proved
            
            avg_children = df[children_col].mean() if children_col else 0.0
            avg_parents = df[parent_col].mean() if parent_col else 0.0

            summary_rows.append({
                'starting_depth': depth_val,
                'total_proving_time': total_duration,
                'total_cycles': total_cycles,
                'packages_proved': total_packages,
                'avg_children_count': avg_children,
                'avg_parents_count': avg_parents,
                'source_file': filename
            })
            print(f"Processed {filename} -> Summed Proving Time: {total_duration:.2f}, Summed Cycles: {total_cycles:,}, Avg Children: {avg_children:.2f}, Avg Parents: {avg_parents:.2f}")
            
        except Exception as e:
            print(f"Error compiling file {filename}: {e}")
            
    if not summary_rows:
        return pd.DataFrame()
        
    summary_df = pd.DataFrame(summary_rows)
    # Sort chronological by starting depth for correct line rendering
    summary_df = summary_df.sort_values(by='starting_depth').reset_index(drop=True)
    return summary_df

# ==========================================
# 2. VISUALIZATION ENGINE
# ==========================================
def plot_whole_update_performance(summary_df):
    if summary_df.empty:
        print("No aggregated data to render.")
        return

    # General styling rules for academic presentation
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 13})
    
    unique_ticks = summary_df['starting_depth'].unique()

    # ----------------------------------------------------
    # GRAPH 1: Standalone Pure Proving Time Figure
    # ----------------------------------------------------
    
    fig, ax1 = plt.subplots(figsize=(8.5, 5.5))
    ax1.grid(True, linestyle='--', alpha=0.6)
    sns.lineplot(data=summary_df, x='starting_depth', y='total_proving_time', 
                 marker='o', markersize=8, color='darkcyan', linewidth=2.5)
    sns.scatterplot(data=summary_df, x='starting_depth', y='total_proving_time', 
                    color='black', s=60, zorder=5)
    
    ax1.set_title("Total Proving Duration & Branching Density per Complete Update", pad=15)
    ax1.set_xlabel("Update Trigger Point (DAG Depth Level)")
    ax1.set_ylabel("Total Cumulative Proving Time (ms)", color='darkcyan')
    ax1.tick_params(axis='y', labelcolor='darkcyan')
    ax1.set_xticks(unique_ticks)

    # Secondary Axis: Avg Children Count
    ax2 = ax1.twinx()
    sns.lineplot(data=summary_df, x='starting_depth', y='avg_children_count', 
                 marker='^', markersize=8, color='crimson', linewidth=2.0, linestyle=':', ax=ax2, label='Avg Children Count')
    sns.scatterplot(data=summary_df, x='starting_depth', y='avg_children_count', 
                    color='black', s=40, zorder=5, ax=ax2)
    
    sns.lineplot(data=summary_df, x='starting_depth', y='avg_parents_count', 
                 marker='v', markersize=8, color='darkorange', linewidth=2.0, linestyle='-.', ax=ax2, label='Avg Parents (In-degree)')
    sns.scatterplot(data=summary_df, x='starting_depth', y='avg_parents_count', 
                    color='black', s=40, zorder=5, ax=ax2)
    
    ax2.set_ylabel("Average Children Count (Branching Factor)", color='crimson')
    ax2.tick_params(axis='y', labelcolor='crimson')

    # Unify Legends from both axes
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper right')

    plt.tight_layout()
    time_out_path = os.path.join(OUTPUT_DIR, "update_proving_time_with_children.png")
    plt.savefig(time_out_path, dpi=300)
    plt.close()
    print(f"[Success] Dual-axis Proving Time graph saved to: {time_out_path}")

    # ----------------------------------------------------
    # GRAPH 2: Standalone zkVM Clock Cycles Figure
    # ----------------------------------------------------
    fig, ax1 = plt.subplots(figsize=(8.5, 5.5))
    ax1.grid(True, linestyle='--', alpha=0.6)
    
    sns.lineplot(data=summary_df, x='starting_depth', y='total_cycles', 
                 marker='s', markersize=8, color='indigo', linewidth=2.5)
    sns.scatterplot(data=summary_df, x='starting_depth', y='total_cycles', 
                    color='black', s=60, zorder=5)
    
    ax1.set_title("Total zkVM Cycles & Branching Density per Complete Update", pad=15)
    ax1.set_xlabel("Update Trigger Point (DAG Depth Level)")
    ax1.set_ylabel("Total Cumulative Cycles Counts", color='indigo')
    ax1.tick_params(axis='y', labelcolor='indigo')
    ax1.set_xticks(unique_ticks)
    ax1.ticklabel_format(style='sci', scilimits=(0,0), axis='y')

    # Secondary Axis: Avg Children Count
    ax2 = ax1.twinx()
    sns.lineplot(data=summary_df, x='starting_depth', y='avg_children_count', 
                 marker='^', markersize=8, color='crimson', linewidth=2.0, linestyle=':', ax=ax2, label='Avg Children Count')
    sns.scatterplot(data=summary_df, x='starting_depth', y='avg_children_count', 
                    color='black', s=40, zorder=5, ax=ax2)
    
    sns.lineplot(data=summary_df, x='starting_depth', y='avg_parents_count', 
                 marker='v', markersize=8, color='darkorange', linewidth=2.0, linestyle='-.', ax=ax2, label='Avg Parents (In-degree)')
    sns.scatterplot(data=summary_df, x='starting_depth', y='avg_parents_count', 
                    color='black', s=40, zorder=5, ax=ax2)
    
    ax2.set_ylabel("Average Children Count (Branching Factor)", color='crimson')
    ax2.tick_params(axis='y', labelcolor='crimson')

    # Unify Legends from both axes
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper right')

    plt.tight_layout()
    cycles_out_path = os.path.join(OUTPUT_DIR, "update_cycles_with_children.png")
    plt.savefig(cycles_out_path, dpi=300)
    plt.close()
    print(f"[Success] Dual-axis zkVM Cycles graph saved to: {cycles_out_path}")
    
# ==========================================
# 3. RUNTIME ENTRYPOINT
# ==========================================
if __name__ == "__main__":
    print("Initializing Whole Update Performance Compiler...")
    
    # Compile cumulative totals across all individual logs
    summary_data = build_summary_dataset(CSV_DIR)
    
    if not summary_data.empty:
        print("\n=== Experiment Summary Table ===")
        print(summary_data[['starting_depth', 'total_proving_time', 'total_cycles', 'packages_proved', 'avg_parents_count']].to_string(index=False))
        
        # Render trend graphs
        plot_whole_update_performance(summary_data)
    else:
        print("\nExecution terminated: No summary dataset could be generated.")
import pandas as pd
import re
import matplotlib.pyplot as plt
import seaborn as sns
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MONITOR_CSV_PATH = os.path.join(SCRIPT_DIR, '../../../../CSV/parallel_opt/express_cpu_monitor.csv')
LOG_CSV_PATH = os.path.join(SCRIPT_DIR, '../../../../CSV/parallel_opt/never_seen/express_experiment_log_v2.csv')

def parse_running_tasks(task_str):
    """
    Extracts component names from the Running_Tasks string.
    Example: "['Proving: mime-db, ...', 'Proving: negotiator, ...']" or "[Proving: mime-db, Proving: negotiator]"
    """
    if pd.isna(task_str) or task_str == '[]':
        return []
    # Regex to find all occurrences of "Proving: <comp_name>,"
    # Looking at the possible format, it might be inside brackets, quotes, etc.
    # We grep the comp_name after "Proving: " before ","
    matches = re.findall(r'Proving:\s*([^,\]\'"]+)', str(task_str))
    return [match.strip() for match in matches]

def process_monitor_data(monitor_path):
    df_monitor = pd.read_csv(monitor_path)
    df_monitor['Timestamp'] = pd.to_datetime(df_monitor['Timestamp'])
    
    # Dictionary to store start and end times for each component
    # Format: { 'comp_name': {'start': timestamp, 'end': timestamp} }
    comp_times = {}

    for index, row in df_monitor.iterrows():
        timestamp = row['Timestamp']
        tasks_str = row['Running_Tasks']
        
        active_comps = parse_running_tasks(tasks_str)
        
        for comp in active_comps:
            if comp not in comp_times:
                # First time seeing this component, set start and end to current timestamp
                comp_times[comp] = {'start': timestamp, 'end': timestamp}
            else:
                # Component is still running, update its end time
                comp_times[comp]['end'] = timestamp

    # Calculate duration for each component
    durations = []
    for comp, times in comp_times.items():
        # Duration in seconds. We add 1 second because if it appears in one timestamp, 
        # it ran for at least that polling interval (assuming 1 sec polling).
        duration_sec = (times['end'] - times['start']).total_seconds() + 1
        durations.append({'comp_name': comp, 'execution_duration_sec': duration_sec})
        
    return pd.DataFrame(durations)

def main():
    if not os.path.exists(MONITOR_CSV_PATH):
        print(f"Error: Monitor CSV not found at {MONITOR_CSV_PATH}")
        return
    if not os.path.exists(LOG_CSV_PATH):
        print(f"Error: Log CSV not found at {LOG_CSV_PATH}")
        return

    # 1. Process Monitor Data to get execution durations
    df_durations = process_monitor_data(MONITOR_CSV_PATH)
    if df_durations.empty:
        print("Warning: No tasks found in monitor data or parsing failed.")
    
    # 2. Process Log Data to get descendants_count and depth
    df_log = pd.read_csv(LOG_CSV_PATH)
    
    # Ensure required columns exist
    required_cols = ['comp_name', 'descendants_count', 'depth']
    for col in required_cols:
        if col not in df_log.columns:
            print(f"Error: Missing column '{col}' in log data.")
            return

    # Remove duplicate comp_names in log if any, keeping the first
    df_log = df_log.drop_duplicates(subset=['comp_name'])

    # Find MAX Depth
    max_depth = df_log['depth'].max()
    print(f"Max Depth found: {max_depth}")

    # Merge DataFrames
    df_merged = pd.merge(df_log, df_durations, on='comp_name', how='inner')
    
    if df_merged.empty:
        print("Warning: Merged dataframe is empty. Check if comp_names match between files.")
        print("Sample comp_names in monitor:", df_durations['comp_name'].head().tolist())
        print("Sample comp_names in log:", df_log['comp_name'].head().tolist())
        return

    # 3. Calculate CBF
    # CBF = descendants_count / (MAX Depth - current depth)
    # Handle division by zero if current depth == MAX Depth
    def calculate_cbf(row):
        denom = max_depth - row['depth']
        if denom == 0:
            return float(row['descendants_count']) # Or handle as needed, e.g., 0 or infinity. Let's use descendants_count or 0.
        return row['descendants_count'] / denom

    df_merged['CBF'] = df_merged.apply(calculate_cbf, axis=1)

    # 4. Calculate average execution duration for each CBF value
    df_avg = df_merged.groupby('CBF')['execution_duration_sec'].mean().reset_index()

    # 5. Plotting
    sns.set_theme(style="whitegrid")
    plt.figure(figsize=(10, 6))
    
    # Scatter plot
    sns.scatterplot(
        data=df_avg, 
        x='CBF', 
        y='execution_duration_sec', 
        s=100, 
        color='steelblue', 
        marker='o',
        alpha=0.8
    )

    plt.title('Average Execution Duration vs CBF', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Component Branching Factor (CBF)', fontsize=12)
    plt.ylabel('Average Execution Duration (seconds)', fontsize=12)
    
    # Annotate points with CBF values (optional, might be crowded if many points)
    # for i, row in df_avg.iterrows():
    #     plt.annotate(f"{row['CBF']:.2f}", (row['CBF'], row['execution_duration_sec']), textcoords="offset points", xytext=(0,5), ha='center', fontsize=8)

    plt.tight_layout()
    out_path = os.path.join(SCRIPT_DIR, 'CBF_vs_Duration.png')
    plt.savefig(out_path, dpi=300)
    plt.close()
    
    print(f"✅ Data processing complete. Graph saved to {out_path}")
    print("\nMerged Data Sample:")
    print(df_merged[['comp_name', 'descendants_count', 'depth', 'CBF', 'execution_duration_sec']].head())

if __name__ == "__main__":
    main()

# I want to verify that, whether the proof size is O(log^2n), where n is cycle
# please get the log from the ../../../CSV/recursive/never_seen/
# x axis is total_cycles, y axis is receipt_size.

import os
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Define paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_DIR = os.path.join(SCRIPT_DIR, '../../../CSV/recursive/never_seen/')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '../../../png/recursive/benchmark/')

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_all_never_seen_data():
    if not os.path.exists(CSV_DIR):
        print(f"Warning: Directory not found: {CSV_DIR}")
        return None
    
    csv_pattern = os.path.join(CSV_DIR, "*_experiment_log.csv")
    csv_files = glob.glob(csv_pattern)
    
    dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f)
            # Ensure required columns exist
            if 'total_cycles' in df.columns and 'receipt_size_kb' in df.columns:
                dfs.append(df[['total_cycles', 'receipt_size_kb']])
        except Exception as e:
            print(f"Error reading {f}: {e}")
            
    if not dfs:
        return None
        
    df_combined = pd.concat(dfs, ignore_index=True)
    # Drop NaNs or invalid values
    df_combined = df_combined.dropna()
    df_combined = df_combined[df_combined['total_cycles'] > 0]
    return df_combined.sort_values(by='total_cycles')

def main():
    df = load_all_never_seen_data()
    if df is None or df.empty:
        print("Error: No valid data found in CSV directory.")
        return
    
    n = df['total_cycles'].values
    y = df['receipt_size_kb'].values
    
    # --- Curve Fitting & R^2 Computation ---
    # 1. Fit O(log^2 n)
    x_log2 = np.log2(n) ** 2
    slope_log2, intercept_log2 = np.polyfit(x_log2, y, 1)
    y_pred_log2 = slope_log2 * x_log2 + intercept_log2
    r2_log2 = 1 - (np.sum((y - y_pred_log2) ** 2) / np.sum((y - np.mean(y)) ** 2))
    
    # 2. Fit O(log n)
    x_log = np.log2(n)
    slope_log, intercept_log = np.polyfit(x_log, y, 1)
    y_pred_log = slope_log * x_log + intercept_log
    r2_log = 1 - (np.sum((y - y_pred_log) ** 2) / np.sum((y - np.mean(y)) ** 2))
    
    # 3. Fit O(n) [Linear]
    slope_lin, intercept_lin = np.polyfit(n, y, 1)
    y_pred_lin = slope_lin * n + intercept_lin
    r2_lin = 1 - (np.sum((y - y_pred_lin) ** 2) / np.sum((y - np.mean(y)) ** 2))
    
    # --- Setup Plotting ---
    sns.set_theme(style="whitegrid")
    plt.figure(figsize=(11, 7))
    plt.rcParams.update({'font.size': 11, 'axes.labelsize': 12, 'axes.titlesize': 14})
    
    # Scatter actual data
    plt.scatter(n, y, color='darkslateblue', alpha=0.6, s=50, label='Empirical Receipts (Data Points)', zorder=3)
    
    # Generate smooth curves for plotting the fitted models
    n_smooth = np.linspace(n.min(), n.max(), 500)
    
    # Plot Fitted O(log^2 n)
    y_smooth_log2 = slope_log2 * (np.log2(n_smooth) ** 2) + intercept_log2
    plt.plot(n_smooth, y_smooth_log2, color='crimson', linewidth=2.5, 
             label=f'O(log^2 n) Fit (R^2 = {r2_log2:.4f})', zorder=4)
             
    # Plot Fitted O(log n)
    y_smooth_log = slope_log * np.log2(n_smooth) + intercept_log
    plt.plot(n_smooth, y_smooth_log, color='forestgreen', linewidth=2, linestyle='--',
             label=f'O(log n) Fit (R^2 = {r2_log:.4f})', zorder=4)
             
    # Plot Fitted O(n)
    y_smooth_lin = slope_lin * n_smooth + intercept_lin
    plt.plot(n_smooth, y_smooth_lin, color='darkorange', linewidth=2, linestyle=':',
             label=f'O(n) Linear Fit (R^2 = {r2_lin:.4f})', zorder=4)
    
    # Title and Labels
    plt.title("RISC Zero Receipt Size Complexity: Empirical Data vs Complexity Models")
    plt.xlabel("Total Cycles (n)")
    plt.ylabel("Receipt Size (KB)")
    
    # Determine the best mathematical model
    models = {
        "O(log^2 n)": r2_log2,
        "O(log n)": r2_log,
        "O(n)": r2_lin
    }
    best_model = max(models, key=models.get)
    
    # Add textual notes on the plot
    text_info = (
        f"=== Complexity Fitting Results ===\n"
        f"O(log^2 n) R^2 Score: {r2_log2:.4f}\n"
        f"O(log n) R^2 Score: {r2_log:.4f}\n"
        f"O(n) Linear R^2 Score: {r2_lin:.4f}\n"
        f"Best Fit Model: {best_model}\n\n"
        f"Conclusion: "
        f"The empirical receipt size is {'indeed' if best_model == 'O(log^2 n)' else 'NOT'} O(log^2 n).\n"
        f"It is best modeled by {best_model}."
    )
    plt.gca().text(0.05, 0.95, text_info, transform=plt.gca().transAxes,
                 fontsize=10, verticalalignment='top', bbox=dict(boxstyle='round,pad=0.5', facecolor='white', alpha=0.9, edgecolor='gray'))
    
    plt.legend(loc='lower right')
    plt.tight_layout()
    
    output_png = os.path.join(OUTPUT_DIR, 'proof_size_vs_cycle.png')
    plt.savefig(output_png, dpi=300)
    plt.close()
    
    print("=== Complexity Analysis ===")
    print(f"O(log^2 n) R^2 Score: {r2_log2:.6f}")
    print(f"O(log n) R^2 Score:   {r2_log:.6f}")
    print(f"O(n) Linear R^2 Score: {r2_lin:.6f}")
    print(f"Best Fitting Complexity Model: {best_model}")
    print(f"Conclusion: Empirical proof size matches {best_model}.")
    print(f"Saved: {output_png}")

if __name__ == '__main__':
    main()

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# ==========================================
# 1. CONFIGURATION & PATHS
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, '../CSV/recursive/profile/semantic-kernel_experiment_log.csv')
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '../png/guest_analysis/')

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==========================================
# 2. LOAD & VALIDATE DATA
# ==========================================
def load_data():
    """Load CSV and validate required columns."""
    if not os.path.exists(CSV_FILE):
        return None
    try:
        return pd.read_csv(CSV_FILE)
    except Exception:
        return None

# ==========================================
# 3. DATA ANALYSIS
# ==========================================
def analyze_variance(df):
    """Find groups with same children_count but different metrics."""
    variance_data = []
    for children_count in sorted(df['children_count'].unique()):
        subset = df[df['children_count'] == children_count]
        if len(subset) > 1:
            duration_std = subset['pure_prove_duration'].std()
            cycles_std = subset['total_cycles'].std()
            
            if duration_std > 0 or cycles_std > 0:
                variance_data.append({
                    'children_count': int(children_count),
                    'samples': len(subset),
                    'duration_min': subset['pure_prove_duration'].min(),
                    'duration_max': subset['pure_prove_duration'].max(),
                    'duration_range': subset['pure_prove_duration'].max() - subset['pure_prove_duration'].min(),
                    'duration_std': duration_std,
                    'cycles_min': subset['total_cycles'].min(),
                    'cycles_max': subset['total_cycles'].max(),
                    'cycles_range': subset['total_cycles'].max() - subset['total_cycles'].min(),
                    'cycles_std': cycles_std,
                })
    return pd.DataFrame(variance_data).sort_values('duration_range', ascending=False)

# ==========================================
# 4. PLOTTING FUNCTIONS
# ==========================================
def plot_children_count_variance(df):
    variance_df = analyze_variance(df)
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Variance Analysis: Same children_count → Different Metrics", fontsize=14, fontweight='bold')
    
    sns.barplot(data=variance_df.head(10), x='children_count', y='duration_range', color='steelblue', ax=axes[0, 0])
    axes[0, 0].set_title("Duration Range by children_count (Top 10)")
    axes[0, 0].set_xlabel("Children Count")
    axes[0, 0].set_ylabel("Duration Range (ms)")
    axes[0, 0].grid(axis='y', alpha=0.3)
    
    sns.barplot(data=variance_df.head(10), x='children_count', y='cycles_range', color='coral', ax=axes[0, 1])
    axes[0, 1].set_title("Cycles Range by children_count (Top 10)")
    axes[0, 1].set_xlabel("Children Count")
    axes[0, 1].set_ylabel("Cycles Range")
    axes[0, 1].grid(axis='y', alpha=0.3)
    
    sns.scatterplot(data=variance_df, x='children_count', y='duration_std', s=100, color='darkgreen', ax=axes[1, 0])
    axes[1, 0].set_title("Duration Std Dev by children_count")
    axes[1, 0].set_xlabel("Children Count")
    axes[1, 0].set_ylabel("Duration Std Dev")
    axes[1, 0].grid(alpha=0.3)
    
    sns.scatterplot(data=variance_df, x='children_count', y='cycles_std', s=100, color='darkred', ax=axes[1, 1])
    axes[1, 1].set_title("Cycles Std Dev by children_count")
    axes[1, 1].set_xlabel("Children Count")
    axes[1, 1].set_ylabel("Cycles Std Dev")
    axes[1, 1].grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "01_variance_analysis.png"), dpi=300, bbox_inches='tight')
    plt.close()

def plot_depth_effect(df):
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Effect of Depth on Proving Performance", fontsize=13, fontweight='bold')
    
    sns.scatterplot(data=df, x='depth', y='pure_prove_duration', hue='children_count', palette='viridis', s=80, ax=axes[0], alpha=0.7)
    axes[0].set_xlabel("Tree Depth")
    axes[0].set_ylabel("Proving Duration (ms)")
    axes[0].set_title("Depth vs Proving Duration")
    axes[0].grid(alpha=0.3)
    axes[0].legend(title='children_count', bbox_to_anchor=(1.05, 1), loc='upper left')
    
    sns.scatterplot(data=df, x='depth', y='total_cycles', hue='children_count', palette='viridis', s=80, ax=axes[1], alpha=0.7)
    axes[1].set_xlabel("Tree Depth")
    axes[1].set_ylabel("Total Cycles")
    axes[1].set_title("Depth vs Total Cycles")
    axes[1].grid(alpha=0.3)
    axes[1].legend(title='children_count', bbox_to_anchor=(1.05, 1), loc='upper left')
    
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "02_depth_effect.png"), dpi=300, bbox_inches='tight')
    plt.close()

def plot_guest_metrics(df):
    fig, axes = plt.subplots(2, 3, figsize=(15, 10))
    fig.suptitle("Guest Code Operation Metrics Distribution", fontsize=13, fontweight='bold')
    
    metrics = ['guest_io_read', 'guest_dependency_check', 'guest_severity_check', 'guest_merkle_io_read', 'guest_merkle_check']
    for idx, metric in enumerate(metrics):
        ax = axes[idx // 3, idx % 3]
        if metric in df.columns:
            sns.boxplot(data=df, y=metric, ax=ax, color='lightblue')
            ax.set_title(f"{metric}")
            ax.set_ylabel("Cycles")
            ax.grid(axis='y', alpha=0.3)
    
    axes[1, 2].remove()
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "03_guest_metrics_distribution.png"), dpi=300, bbox_inches='tight')
    plt.close()

def plot_correlation_heatmap(df):
    numeric_df = df.select_dtypes(include=[np.number]).copy()
    if 'pure_prove_duration' in numeric_df.columns:
        correlations = numeric_df.corr()['pure_prove_duration'].sort_values(ascending=False)
        fig, ax = plt.subplots(figsize=(12, 6))
        colors = ['green' if x > 0 else 'red' for x in correlations.values]
        sns.barplot(x=correlations.values, y=correlations.index, palette=colors, ax=ax)
        ax.set_title("Correlation with Proving Duration", fontsize=13, fontweight='bold')
        ax.set_xlabel("Correlation Coefficient")
        ax.axvline(x=0, color='black', linestyle='-', linewidth=0.5)
        ax.grid(axis='x', alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, "04_correlation_heatmap.png"), dpi=300, bbox_inches='tight')
        plt.close()

def plot_scatter_matrix(df):
    key_cols = ['children_count', 'depth', 'parent_count', 'pure_prove_duration', 'total_cycles']
    available_cols = [col for col in key_cols if col in df.columns]
    if len(available_cols) >= 3:
        subset_df = df[available_cols].copy()
        fig, ax = plt.subplots(figsize=(12, 8))
        scatter = ax.scatter(subset_df['children_count'], subset_df['pure_prove_duration'],
                           c=subset_df['depth'], s=subset_df['total_cycles']/1000,
                           cmap='viridis', alpha=0.6, edgecolors='black', linewidth=0.5)
        ax.set_xlabel("Children Count", fontsize=11)
        ax.set_ylabel("Proving Duration (ms)", fontsize=11)
        ax.set_title("Multi-dimensional Relationship Analysis\n(Color=Depth, Size=Cycles)", fontsize=12, fontweight='bold')
        ax.grid(alpha=0.3)
        cbar = plt.colorbar(scatter, ax=ax)
        cbar.set_label("Tree Depth", fontsize=10)
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, "05_scatter_matrix.png"), dpi=300, bbox_inches='tight')
        plt.close()

# ==========================================
# 5. MAIN FUNCTION
# ==========================================
def main():
    df = load_data()
    if df is not None:
        sns.set_theme(style="whitegrid")
        plt.rcParams.update({'font.size': 10, 'axes.labelsize': 11, 'axes.titlesize': 12})
        plot_children_count_variance(df)
        plot_depth_effect(df)
        plot_guest_metrics(df)
        plot_correlation_heatmap(df)
        plot_scatter_matrix(df)

if __name__ == "__main__":
    main()
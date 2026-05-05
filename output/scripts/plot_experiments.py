import pandas as pd
import matplotlib.pyplot as plt
import os

# Define paths relative to the script location
script_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(script_dir, '../CSV/sequential/experiment_log.csv')
output_dir = os.path.join(script_dir, '../png')

def plot_experiments():
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at {csv_path}")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return

    if df.empty:
        print("CSV is empty, skipping plotting.")
        return

    # List of (x, y) pairs to plot
    # time refers to pure_proving_duration
    plots = [
        ('cycle', 'depth'),
        ('pure_proving_duration', 'depth'),
        ('cycle', 'children_count'),
        ('pure_proving_duration', 'children_count'),
        ('cycle', 'receipt_size_kb'),
        ('cycle', 'seal_size_kb'),
        ('pure_proving_duration', 'receipt_size_kb'),
        ('pure_proving_duration', 'seal_size_kb'),
        ('pure_proving_duration', 'cycle')
    ]

    for x, y in plots:
        if x not in df.columns or y not in df.columns:
            print(f"Skipping plot ({x}, {y}): Column(s) missing.")
            continue

        plt.figure(figsize=(10, 6))
        plt.scatter(df[x], df[y], alpha=0.5)
        plt.title(f'{y} vs {x}')
        plt.xlabel(x)
        plt.ylabel(y)
        plt.grid(True)
        
        # Sanitize filename
        filename = f'{y}_{x}.png'.replace('/', '_')
        save_path = os.path.join(output_dir, filename)
        plt.savefig(save_path)
        plt.close()
        print(f"Saved plot: {save_path}")

if __name__ == "__main__":
    plot_experiments()

# Open Sources	Speedup	Avg.\operatorname{d}_{out}	VAR(\operatorname{d}_{out}\ )
# Express.js	1.28	2.2414	5.4167
# Flask	1.58	4.3514	4.3695
# NeMo	1.35	4.3185	12.7504
# Semantic-Kernel	1.61	3.9609	5.0819
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patheffects as pe

# 1. 準備實驗數據
data = {
    'Open_Source': ['Express.js', 'Flask', 'NeMo', 'Semantic-Kernel'],
    'Speedup': [1.28, 1.58, 1.35, 1.61],
    'Avg_d_out': [2.2414, 4.3514, 4.3185, 3.9609],
    'VAR_d_out': [5.4167, 4.3695, 12.7504, 5.0819]
}

df = pd.DataFrame(data)

# 2. 啟動繪圖引擎
fig, ax1 = plt.subplots(figsize=(10, 6))

color1 = '#1f77b4' 
ax1.set_xlabel(r'Average Out-degree ($Avg. d_{out}$)', fontsize=12, fontweight='bold')
ax1.set_ylabel(r'Variance of Out-degree ($VAR(d_{out})$)', fontsize=12, fontweight='bold')

# 畫出散佈點
ax1.scatter(df['Avg_d_out'], df['VAR_d_out'], color=color1, s=150, zorder=5, label=r'Project Topology')

# 💡 學術細節：專屬的標籤偏移量 (徹底錯開 SK 與 Flask)
label_offsets = {
    'Express.js': (0, 20),
    'Flask': (0, -25),         
    'NeMo': (0, 20),           
    'Semantic-Kernel': (0, 20) 
}

# 💡 進階技巧：設定文字的白邊效果，取代原本的 BBox 框，讓文字在格線上依然清晰
path_effects = [pe.withStroke(linewidth=3, foreground="white")]

# 3. 畫出投影虛線與分色文字標籤
for idx, row in df.iterrows():
    project_name = row['Open_Source']
    speedup_val = row['Speedup']
    
    # 投影虛線
    ax1.plot([row['Avg_d_out'], row['Avg_d_out']], [0, row['VAR_d_out']], 
             linestyle=':', color='gray', zorder=1, alpha=0.7)
    ax1.plot([0, row['Avg_d_out']], [row['VAR_d_out'], row['VAR_d_out']], 
             linestyle=':', color='gray', zorder=1, alpha=0.7)
    
    custom_offset = label_offsets.get(project_name, (0, 20))
    
    # 計算第二行(Speedup)的 Y 偏移量
    # 如果原本標籤是在下方 (如 Flask), 則第一行(專案名)要再往下移，避免撞到圓點
    if custom_offset[1] < 0:
        y_offset_proj = custom_offset[1] - 12
        y_offset_speedup = custom_offset[1] - 26
    else:
        y_offset_proj = custom_offset[1] + 12
        y_offset_speedup = custom_offset[1]
        
    # 標註專案名稱 (黑色，帶白邊)
    ax1.annotate(project_name, (row['Avg_d_out'], row['VAR_d_out']), 
                 textcoords="offset points", xytext=(custom_offset[0], y_offset_proj), 
                 ha='center', fontsize=11, fontweight='bold', color='black',
                 path_effects=path_effects, zorder=6)
                 
    # 標註 Speedup (紅色，帶白邊)
    speedup_text = f"Speedup: {speedup_val}x"
    ax1.annotate(speedup_text, (row['Avg_d_out'], row['VAR_d_out']), 
                 textcoords="offset points", xytext=(custom_offset[0], y_offset_speedup), 
                 ha='center', fontsize=10, fontweight='bold', color='#d62728', # 學術常用的醒目紅
                 path_effects=path_effects, zorder=6)

# 4. 邊界設定與收尾
ax1.set_xlim(left=0, right=max(df['Avg_d_out']) * 1.15)
ax1.set_ylim(bottom=0, top=max(df['VAR_d_out']) * 1.15)

ax1.legend(loc='upper left', framealpha=0.9)
ax1.grid(True, linestyle='--', alpha=0.3, zorder=0)

plt.title('Impact of DAG Topology on Parallel Speedup', fontsize=14, fontweight='bold', pad=15)
fig.tight_layout()
plt.savefig('speedup_scatter_red_text.png', dpi=300)
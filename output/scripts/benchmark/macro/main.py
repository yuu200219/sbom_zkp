import os
import subprocess

files = os.listdir('.')

for file in files:
    # 篩選出 .py 檔案且排除自己
    if file.endswith('.py') and file != 'main.py':
        print(f'開始執行: {file}')
        # 執行該檔案並等待它完成
        subprocess.run(['python3', file]) 

print('所有腳本執行完畢！')
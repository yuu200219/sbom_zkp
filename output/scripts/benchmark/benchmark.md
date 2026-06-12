# Benchmark
從 `../../CSV/recursive/never_seen/` 資料夾讀取資料。將會是 batch input 這些 csv file。之後我再自己於 code 中輸入 csv file name。
每個 csv file 都代表是一個 package 的證明 log，裡面會有多個欄位，而以下的實驗都是根據這些欄位去畫圖。
```
total_cycles,user_cycles,segments,depth,pure_prove_duration,children_count,parent_count,descendants_count,receipt_size_kb,seal_size_kb,compression_duration,guest_io_read,guest_dependency_check,guest_severity_check,guest_merkle_io_read,guest_merkle_check,comp_name,cid
```
coding/plotting style 可以參考 `../plot_experiments_v2.py`.
output: ../../png/recursive/
## Macro Benchmark
目標是要展示：實用性（Practicality）與可擴展性（Scalability）
- End-to-end scalability
    - `prove_duration_vs_children_count.py`
        - x axis: `children_count`, y axis: `pure_prove_duration`
        - 每個 package 會是一個顏色的點，使用 `sns.scatterplot`。
        - 透過 `sns.lineplot` 畫 avg prove duration。
    - `prove_duration_vs_depth.py`
        - x axis: `depth`, y axis: `pure_prove_duration`
        - 每個 package 會是一個顏色的點，使用 `sns.scatterplot`。
        - 透過 `sns.lineplot` 畫 avg prove duration。
    - `prove_duration_vs_descendants_count.py`
        - x axis: `descendants_count`, y axis: `pure_prove_duration`
        - 每個 package 會是一個顏色的點，使用 `sns.scatterplot`。
        - 透過 `sns.lineplot` 畫 avg prove duration。
    - `cycles_vs_children_count.py`
        - x axis: `children_count`, y axis: `user_cycles` and `total_cycles` and `overhead_cycles`(`total_cycles` - `user_cycels`)
        - 每個 package 會是一個顏色的點，使用 `sns.scatterplot`。
        - 透過 `sns.lineplot` 畫 avg prove duration。

    - `cycles_vs_depth.py`
        - x axis: `depth`, y axis: `user_cycles` and `total_cycles` and `overhead_cycles`(`total_cycles` - `user_cycels`)
        - 每個 package 會是一個顏色的點，使用 `sns.scatterplot`。
        - 透過 `sns.lineplot` 畫 avg prove duration。
    - `cycles_vs_descendants_count.py`
        - x axis: `descendants_count`, y axis: `user_cycles` and `total_cycles` and `overhead_cycles`(`total_cycles` - `user_cycels`)
        - 每個 package 會是一個顏色的點，使用 `sns.scatterplot`。
        - 透過 `sns.lineplot` 畫 avg prove duration。
- Parallel Orchestration Efficiency (ignore for now!)
    - Sequential (32 cores run 1 proof)
    - Parallel (per 4 tasks 8 cores / per 9 tasks 4 cores)
- Compression with CPU/GPU (ignore for now!)
    - 這邊透過 m2 chip 來跑，手邊資源有限

## Micro Benchmark
- correlation_heatmap
    - 觀察 receipt_size 實際上是什麼 metric 影響？（我們在乎要消耗多少空間）
    - 觀察 prove_duration 實際上是什麼 metric 影響？（我們在乎實際上要花多少時間）
    - 以 receipt_size / pure_prove_duration 為基準，比較每個 metrics 跟他們的關係。
- Cycle profiling (I/O read, dependency check, severity check, membership check)
    - bottleneck 出現在 I/O?
    - 可以畫出 stack bar chart
    - x axis: children_count/descendants_count, y: corresponding metric cycles
- Show the Trade-off (ignore for now!)

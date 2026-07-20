# Getting started with Rust Prover API
## run rust-prove-api
```bash
cargo build -p host
cargo run -p host --release
```
## Rust Docments references
### Executing the Project Locally in Development Mode

During development, faster iteration upon code changes can be achieved by leveraging [dev-mode], we strongly suggest activating it during your early development phase. Furthermore, you might want to get insights into the execution statistics of your project, and this can be achieved by specifying the environment variable `RUST_LOG="[executor]=info"` before running your project.

Put together, the command to run your project in development mode while getting execution statistics is:

```bash
RUST_LOG="[executor]=info" RISC0_DEV_MODE=1 cargo run
```
## Directory Structure

It is possible to organize the files for these components in various ways.
However, in this starter template we use a standard directory structure for zkVM
applications, which we think is a good starting point for your applications.

```text
project_name
├── Cargo.toml
├── host
│   ├── Cargo.toml
│   └── src
│       └── main.rs                    <-- [Host code goes here]
└── methods
    ├── Cargo.toml
    ├── build.rs
    ├── guest
    │   ├── Cargo.toml
    │   └── src
    │       └── method_name.rs         <-- [Guest code goes here]
    └── src
        └── lib.rs
```

### Explaination the code
In host side, we modified the `rust-prover-opt`, adding `rayon` to create the pool. Our machine has 32 cores, so we divide into 4 groups, each group has 8 cores(threads). Using `pool.install` to trigger the individual environemnt for each group. For each `dep` under component, we push the `prove_component_recursive(dep)` job into `child_futures`, which type is `Vec<Impl Future>`. After that, using `futures::future::try_join_all(child_futures).await?` to trigger concurrent task. All the child instance, which are independent, will start run `prove_comonent_recursive` concurrently. This implementation will achieve the parallel goal.

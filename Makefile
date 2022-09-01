default: ci

ci: fmt check-no-std clippy test bench-test

test: test-leaves-only test-node-proofs

test-leaves-only:
	cargo test --all

test-node-proofs:
	cargo test --all --all-features

bench-test:
	cargo bench -- --test

clippy:
	cargo clippy  --all --all-features --all-targets

fmt:
	cargo fmt --all -- --check

check-no-std:
	cargo check --all --no-default-features

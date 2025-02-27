# https://github.com/casey/just

# list things
default: list

# List the options
list:
    just --list

# Run it
run:
    cargo run --

# Run all the checks
check: codespell clippy test doc_check


# Spell check the things
codespell:
    codespell -c \
    --ignore-words .codespell_ignore \
    --skip='./target' \
    --skip='./Cargo.lock' \
    --skip='./tarpaulin-report.html' \
    --skip='./static/*' \
    --skip='./.git'

# Ask the clip for the judgement
clippy:
    cargo clippy --all-features

test:
    cargo test

# Things to do before a release
release_prep: check semgrep
    cargo deny check
    cargo build --release

# Semgrep things
semgrep:
    semgrep ci --config auto \
    --exclude-rule "yaml.github-actions.security.third-party-action-not-pinned-to-commit-sha.third-party-action-not-pinned-to-commit-sha" \
    --exclude-rule "generic.html-templates.security.var-in-script-tag.var-in-script-tag" \
    --exclude-rule "javascript.express.security.audit.xss.mustache.var-in-href.var-in-href" \
    --exclude-rule "python.django.security.django-no-csrf-token.django-no-csrf-token" \
    --exclude-rule "python.django.security.audit.xss.template-href-var.template-href-var" \
    --exclude-rule "python.django.security.audit.xss.var-in-script-tag.var-in-script-tag" \
    --exclude-rule "python.flask.security.xss.audit.template-href-var.template-href-var" \
    --exclude-rule "python.flask.security.xss.audit.template-href-var.template-href-var"

# Build the rustdocs
doc:
	cargo doc --document-private-items

# Run cargo tarpaulin
coverage:
    cargo tarpaulin --out Html
    @echo "Coverage file at file://$(PWD)/tarpaulin-report.html"

# Run cargo tarpaulin and upload to coveralls
coveralls:
    cargo tarpaulin --coveralls $COVERALLS_REPO_TOKEN

# Check docs format
doc_check:
	find . -type f  \
		-not -path './target/*' \
		-not -path './docs/*' \
		-not -path '*/.venv/*' -not -path './vendor/*'\
		-not -path '*/.*/*' \
		-name \*.md \
		-exec deno fmt --check --options-line-width=100 "{}" +

# Fix docs formatting
doc_fix:
	find . -type f  -not -path './target/*' -not -path '*/.venv/*' -not -path './vendor/*'\
		-name \*.md \
		-exec deno fmt --options-line-width=100 "{}" +

# Run trivy on the repo
trivy_repo:
    trivy repo $(pwd) --skip-dirs 'target/**' --skip-files .envrc -d
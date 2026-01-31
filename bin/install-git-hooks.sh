#!/bin/bash

# Install Git Hooks
# This script installs pre-commit and pre-push hooks in .git/hooks/
# Run this after cloning the repository to enable validation hooks.

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"
SOURCE_DIR="$REPO_ROOT/bin/git-hooks"

echo "Installing git hooks from $SOURCE_DIR..."

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Install pre-commit hook
echo "Installing pre-commit hook..."
if [ -f "$SOURCE_DIR/pre-commit" ]; then
    cp "$SOURCE_DIR/pre-commit" "$HOOKS_DIR/pre-commit"
    chmod +x "$HOOKS_DIR/pre-commit"
    echo "✓ pre-commit hook installed"
else
    echo "✗ pre-commit hook not found at $SOURCE_DIR/pre-commit"
    exit 1
fi

# Install pre-push hook
echo "Installing pre-push hook..."
if [ -f "$SOURCE_DIR/pre-push" ]; then
    cp "$SOURCE_DIR/pre-push" "$HOOKS_DIR/pre-push"
    chmod +x "$HOOKS_DIR/pre-push"
    echo "✓ pre-push hook installed"
else
    echo "✗ pre-push hook not found at $SOURCE_DIR/pre-push"
    exit 1
fi

echo ""
echo "✓ All git hooks installed successfully!"
echo ""
echo "Installed hooks:"
echo "  • pre-commit: Validates YAML syntax before commit"
echo "  • pre-push: Runs full validation before push"
echo ""
echo "To bypass hooks: git commit/push --no-verify"
echo "To uninstall: rm $HOOKS_DIR/{pre-commit,pre-push}"

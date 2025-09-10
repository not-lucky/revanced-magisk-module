
# CRUSH.md - revanced-magisk-module

## Build/Lint/Test Commands

*   **Build:**
    *   `./build.sh` - Main build script.
    *   `./build-termux.sh` - Build script specifically for Termux environment.

*   **Lint:**
    *   `shellcheck build.sh revanced-magisk/*.sh utils.sh` - Basic shell script linting. Install `shellcheck` if not available.

*   **Test:**
    *   No automated test suite identified. Manual testing is currently required.
    *   To test individual scripts, run them directly (e.g., `./revanced-magisk/customize.sh`).

## Code Style Guidelines

*   **Language:** Primarily Bash/shell scripting.
*   **Formatting:**
    *   Indent with 4 spaces.
    *   Use consistent newline characters (LF).
    *   Keep lines reasonably short (under 100-120 characters).
*   **Naming Conventions:**
    *   Variables: `UPPER_SNAKE_CASE` for global/environment variables, `lower_snake_case` for local variables.
    *   Functions: `lower_snake_case` or `kebab-case`.
*   **Error Handling:**
    *   Use `set -e` at the beginning of scripts to exit on error.
    *   Implement basic error checks (e.g., `if ! command -v some_tool &> /dev/null; then echo "Error: some_tool not found."; exit 1; fi`).
*   **Comments:** Use `#` for single-line comments. Explain complex logic or non-obvious steps.
*   **Includes/Dependencies:** Source other shell scripts using `source` or `.` (e.g., `. utils.sh`).

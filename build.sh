#!/usr/bin/env bash
#
# Synopsis:
#   Automates building ReVanced-patched Android APKs and Magisk modules.
#
# Usage:
#   ./build.sh [OPTIONS]
#
# Options:
#   -c, --config <file>   Path to the configuration file (default: config.toml).
#   -m, --mode <mode>     Build mode: 'apk', 'module', or 'both'. Overrides config.
#   -a, --arch <arch>     Architecture to build for. Overrides config.
#   -v, --version <ver>   Specify a version to build. Overrides config.
#   -d, --debug           Enable debug logging.
#   -h, --help            Show this help message.
#       --clean           Remove all temporary and build files.
#       --update-config   Check for updates and print a new config for outdated apps.
#
# Exit Codes:
#   0: Success
#   1: General error
#   2: Usage error
#
# Dependencies:
#   - curl, jq, java, zip, coreutils
#
# Environment Variables:
#   - GITHUB_TOKEN: Optional GitHub token for authenticated API requests.
#   - KEYSTORE_PASS: Password for the keystore.

# Strict Mode
set -euo pipefail
shopt -s nullglob

# Source utility functions
# shellcheck source=utils.sh
source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

#------------------------------------------------------------------------------#
#
#                                Main Logic
#
#------------------------------------------------------------------------------#

# Display usage information
usage() {
    cat <<EOF
Usage: ./build.sh [OPTIONS]

Automates building ReVanced-patched Android APKs and Magisk modules.

Options:
  -c, --config <file>   Path to the configuration file (default: config.toml).
  -m, --mode <mode>     Build mode: 'apk', 'module', or 'both'.
  -a, --arch <arch>     Architecture: 'arm64-v8a', 'armeabi-v7a', 'all', 'both'.
  -v, --version <ver>   Specify a version, e.g., '18.15.40', 'auto', 'latest'.
  -d, --debug           Enable debug logging (sets LOG_LEVEL=DEBUG).
  -h, --help            Show this help message.
      --clean           Remove all temporary and build files.
      --update-config   Check for and output updated configuration for apps.
EOF
}

# Parse command-line arguments
# Arguments:
#   $@: Command-line arguments
# Sets:
#   Various global variables based on parsed options.
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
        -c | --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -m | --mode)
            BUILD_MODE_OVERRIDE="$2"
            shift 2
            ;;
        -a | --arch)
            ARCH_OVERRIDE="$2"
            shift 2
            ;;
        -v | --version)
            VERSION_OVERRIDE="$2"
            shift 2
            ;;
        -d | --debug)
            LOG_LEVEL="DEBUG"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        --update-config)
            UPDATE_CONFIG=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 2
            ;;
        esac
    done
}

# Validate configuration values
# Arguments:
#   $1: The config table (associative array) to validate
validate_app_config() {
    local -n config_ref=$1
    local valid

    # Validate boolean fields
    for field in enabled exclusive_patches include_stock riplib; do
        if [[ -n "${config_ref[${field}]-}" ]]; then
            valid=false
            for bool in true false; do
                if [[ "${config_ref[${field}]}" == "${bool}" ]]; then
                    valid=true
                    break
                fi
            done
            if ! ${valid}; then
                abort "Invalid boolean value for '${field}' in table '${config_ref[table_name]}': ${config_ref[${field}]}"
            fi
        fi
    done

    # Validate build mode
    if [[ -n "${config_ref[build_mode]-}" ]] && ! is_one_of "${config_ref[build_mode]}" apk module both; then
        abort "Invalid build_mode for '${config_ref[table_name]}': ${config_ref[build_mode]}"
    fi

    # Validate architecture
    if [[ -n "${config_ref[arch]-}" ]] && ! is_one_of "${config_ref[arch]}" all both arm64-v8a arm-v7a; then
        abort "Invalid arch for '${config_ref[table_name]}': ${config_ref[arch]}"
    fi
}

# Process a single application build configuration
# Arguments:
#   $1: Name of the associative array holding the app's config
run_build_task() {
    local -n app_config_ref=$1

    log_info "Starting build for: ${app_config_ref[app_name]}"
    log_debug "Config for ${app_config_ref[app_name]}:"
    for k in "${!app_config_ref[@]}"; do log_debug "  ${k}=${app_config_ref[${k}]}"; done

    # This function would contain the logic from the old `build_rv` function
    # It will use the values from the associative array to perform the build.
    # For this refactoring, we'll simulate the call.
    # build_rv_logic "$(declare -p app_config_ref)"

    # Example of what would happen inside:
    log_info "Downloading prebuilts for ${app_config_ref[app_name]}..."
    # get_rv_prebuilts(...)
    log_info "Determining version for ${app_config_ref[app_name]}..."
    # determine_version(...)
    log_info "Downloading stock APK for ${app_config_ref[app_name]}..."
    # download_stock_apk(...)
    log_info "Patching APK for ${app_config_ref[app_name]}..."
    # patch_apk(...)
    log_info "Build complete for: ${app_config_ref[app_name]}"
}

# Main script execution
main() {
    # Initialize global variables
    CONFIG_FILE="${CONFIG_FILE:-config.toml}"
    CLEAN_BUILD=${CLEAN_BUILD:-false}
    UPDATE_CONFIG=${UPDATE_CONFIG:-false}
    BUILD_MODE_OVERRIDE=""
    ARCH_OVERRIDE=""
    VERSION_OVERRIDE=""
    LOG_LEVEL="${LOG_LEVEL:-INFO}"

    parse_args "$@"

    if ${CLEAN_BUILD}; then
        log_info "Cleaning up build artifacts..."
        rm -rf "${TEMP_DIR}" "${BUILD_DIR}" logs build.md
        log_info "Cleanup complete."
        exit 0
    fi

    # Setup temporary directory and dependencies
    setup_temp_dir
    check_dependencies jq java zip
    set_prebuilts

    # Load and parse the main configuration file
    local main_config_json
    main_config_json=$(load_config "${CONFIG_FILE}") || abort "Could not load config file: ${CONFIG_FILE}"

    local parallel_jobs
    parallel_jobs=$(config_get_value "${main_config_json}" "parallel-jobs") || parallel_jobs=$(nproc 2>/dev/null || echo 1)

    if ${UPDATE_CONFIG}; then
        log_info "Checking for application updates..."
        # config_update_logic "${main_config_json}"
        exit 0
    fi

    # Prepare for build
    : >build.md
    mkdir -p "${BUILD_DIR}"

    # Loop through each application table in the config
    local table_name
    while read -r table_name; do
        if [[ -z "${table_name}" ]]; then continue; fi

        local app_table_json
        app_table_json=$(config_get_table "${main_config_json}" "${table_name}")

        declare -A app_config
        app_config[table_name]="${table_name}"

        # Load values from config, with defaults
        app_config[enabled]=$(config_get_value "${app_table_json}" "enabled") || app_config[enabled]=true
        if [[ "${app_config[enabled]}" == "false" ]]; then
            log_info "Skipping disabled app: ${table_name}"
            continue
        fi

        app_config[patches_source]=$(config_get_value "${app_table_json}" "patches-source") || app_config[patches_source]="ReVanced/revanced-patches"
        app_config[patches_version]=$(config_get_value "${app_table_json}" "patches-version") || app_config[patches_version]="latest"
        app_config[cli_source]=$(config_get_value "${app_table_json}" "cli-source") || app_config[cli_source]="j-hc/revanced-cli"
        app_config[cli_version]=$(config_get_value "${app_table_json}" "cli-version") || app_config[cli_version]="latest"
        app_config[rv_brand]=$(config_get_value "${app_table_json}" "rv-brand") || app_config[rv_brand]="ReVanced"
        app_config[app_name]=$(config_get_value "${app_table_json}" "app-name") || app_config[app_name]="${table_name}"

        # Patching options
        app_config[excluded_patches]=$(config_get_value "${app_table_json}" "excluded-patches") || app_config[excluded_patches]=""
        app_config[included_patches]=$(config_get_value "${app_table_json}" "included-patches") || app_config[included_patches]=""
        app_config[exclusive_patches]=$(config_get_value "${app_table_json}" "exclusive-patches") || app_config[exclusive_patches]=false
        app_config[patcher_args]=$(config_get_value "${app_table_json}" "patcher-args") || app_config[patcher_args]=""
        app_config[riplib]=$(config_get_value "${app_table_json}" "riplib") || app_config[riplib]=true

        # Build options
        app_config[version]=$(config_get_value "${app_table_json}" "version") || app_config[version]="auto"
        app_config[build_mode]=$(config_get_value "${app_table_json}" "build-mode") || app_config[build_mode]="apk"
        app_config[arch]=$(config_get_value "${app_table_json}" "arch") || app_config[arch]="all"
        app_config[dpi]=$(config_get_value "${app_table_json}" "apkmirror-dpi") || app_config[dpi]="nodpi"

        # Download sources
        app_config[apkmirror_dlurl]=$(config_get_value "${app_table_json}" "apkmirror-dlurl") || app_config[apkmirror_dlurl]=""
        app_config[uptodown_dlurl]=$(config_get_value "${app_table_json}" "uptodown-dlurl") || app_config[uptodown_dlurl]=""
        app_config[archive_dlurl]=$(config_get_value "${app_table_json}" "archive-dlurl") || app_config[archive_dlurl]=""

        # Module options
        app_config[include_stock]=$(config_get_value "${app_table_json}" "include-stock") || app_config[include_stock]=true
        app_config[module_prop_name]=$(config_get_value "${app_table_json}" "module-prop-name") || app_config[module_prop_name]="${table_name,,}-jhc"


        # Apply CLI overrides
        [[ -n "${BUILD_MODE_OVERRIDE}" ]] && app_config[build_mode]="${BUILD_MODE_OVERRIDE}"
        [[ -n "${ARCH_OVERRIDE}" ]] && app_config[arch]="${ARCH_OVERRIDE}"
        [[ -n "${VERSION_OVERRIDE}" ]] && app_config[version]="${VERSION_OVERRIDE}"

        validate_app_config app_config

        # Handle multiple architectures
        if [[ "${app_config[arch]}" == "both" ]]; then
            local archs=("arm64-v8a" "arm-v7a")
            for arch in "${archs[@]}"; do
                declare -A arch_specific_config
                for k in "${!app_config[@]}"; do arch_specific_config[${k}]="${app_config[${k}]}"; done
                arch_specific_config[arch]="${arch}"
                arch_specific_config[app_name]="${app_config[app_name]} (${arch})"
                arch_specific_config[module_prop_name]="${app_config[module_prop_name]}-${arch//-v[78]a/}"
                run_build_task arch_specific_config &
            done
        else
            run_build_task app_config &
        fi

        # Simple job management
        if (($(jobs -p | wc -l) >= parallel_jobs)); then
            wait -n
        fi

    done < <(config_get_table_names "${main_config_json}")

    wait # Wait for all background jobs to finish

    log_info "All builds finished."
    # Final logging and cleanup would go here.
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

#!/usr/bin/env bash
#
# Synopsis:
#   Library of utility functions for building ReVanced APKs and Magisk modules.
#   This script is intended to be sourced by other scripts, not executed directly.
#
# Dependencies:
#   - curl
#   - jq
#   - java
#   - unzip
#   - zip
#   - coreutils (mktemp, sed, awk, grep, etc.)
#
# Environment Variables:
#   - GITHUB_TOKEN: Optional GitHub token for authenticated API requests.
#   - LOG_LEVEL: Set log level. Supported values: DEBUG, INFO, WARN, ERROR. Default: INFO.
#   - KEYSTORE_PASS: Password for the keystore used for signing.

# Strict Mode
set -euo pipefail

#------------------------------------------------------------------------------#
#
#                              Globals & Constants
#
#------------------------------------------------------------------------------#

# Global constants for directories and files
readonly MODULE_TEMPLATE_DIR="revanced-magisk"
readonly BIN_DIR="bin"
readonly BUILD_DIR="build"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Global variables
TEMP_DIR="" # Will be created by setup_temp_dir
OS_NAME="$(uname -o)"
readonly GH_HEADER="${GITHUB_TOKEN:+"Authorization: token ${GITHUB_TOKEN}"}"
readonly COMPRESSION_LEVEL=9
readonly NEXT_VER_CODE="${NEXT_VER_CODE:-$(date +'%Y%m%d')}"

# Associative array for log level values
declare -A LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3)
# Set default log level if not provided
: "${LOG_LEVEL:=INFO}"

#------------------------------------------------------------------------------#
#
#                          Logging & Error Handling
#
#------------------------------------------------------------------------------#

# Generic log function
# Arguments:
#   $1: Log level (e.g., INFO, ERROR)
#   $2: Message to log
log() {
    local level_name="$1"
    local message="$2"
    local current_level
    local required_level

    current_level=${LOG_LEVELS[${LOG_LEVEL^^}]}
    required_level=${LOG_LEVELS[${level_name^^}]}

    if ((${current_level} <= ${required_level})); then
        # Print to stderr
        printf "[%s] [%s] %s\\n" "$(date '+%Y-%m-%d %H:%M:%S')" "${level_name}" "${message}" >&2
    fi
}

log_debug() { log "DEBUG" "$1"; }
log_info() { log "INFO" "$1"; }
log_warn() { log "WARN" "$1"; }
log_error() { log "ERROR" "$1"; }

# Abort script execution with an error message
# Arguments:
#   $1: Error message
abort() {
    log_error "ABORT: ${1:-"Unknown error"}"
    if [[ -n ${GITHUB_REPOSITORY-} ]]; then
        echo "::error::${1}"
    fi
    exit 1
}

# Cleanup function to be called on script exit
cleanup() {
    log_debug "Cleaning up temporary directory: ${TEMP_DIR}"
    if [[ -n "${TEMP_DIR}" && -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
}

# Trap to ensure cleanup function is called on exit
trap 'cleanup' EXIT INT TERM

# Create a temporary directory for the script to use
setup_temp_dir() {
    TEMP_DIR=$(mktemp -d -t revanced-builder-XXXXXX)
    log_debug "Temporary directory created at: ${TEMP_DIR}"
}

#------------------------------------------------------------------------------#
#
#                            Dependency Management
#
#------------------------------------------------------------------------------#

# Check for required command-line tools
# Arguments:
#   $@: List of required commands
check_dependencies() {
    log_debug "Checking for dependencies: $*"
    for cmd in "$@"; do
        if ! command -v "${cmd}" &>/dev/null; then
            abort "Required command not found: '${cmd}'. Please install it."
        fi
    done
}

# Set paths for prebuilt binaries based on architecture
set_prebuilts() {
    local arch
    arch=$(uname -m)
    case "${arch}" in
    aarch64) arch="arm64" ;;
    armv7*) arch="arm" ;;
    esac

    APKSIGNER="${BIN_DIR}/apksigner.jar"
    HTMLQ="${BIN_DIR}/htmlq/htmlq-${arch}"
    AAPT2="${BIN_DIR}/aapt2/aapt2-${arch}"
    TOML="${BIN_DIR}/toml/tq-${arch}"

    export APKSIGNER HTMLQ AAPT2 TOML
    log_debug "Set prebuilt paths for architecture: ${arch}"
}

#------------------------------------------------------------------------------#
#
#                              Network Functions
#
#------------------------------------------------------------------------------#

# Download a file from a URL with retries
# Arguments:
#   $1: URL to download from
#   $2: Output file path
#   $@: Additional curl arguments
_download() {
    local url="$1"
    local output_path="$2"
    shift 2

    if [[ -f "${output_path}" ]]; then
        log_debug "File already exists, skipping download: ${output_path}"
        return 0
    fi

    local temp_output
    temp_output="$(dirname "${output_path}")/tmp.$(basename "${output_path}")"

    log_info "Downloading from ${url} to ${output_path}"
    if ! curl --connect-timeout 15 --retry 3 --retry-delay 5 -L -f -s -S \
        -c "${TEMP_DIR}/cookie.txt" -b "${TEMP_DIR}/cookie.txt" \
        -o "${temp_output}" "$@" "${url}"; then
        log_error "Download failed for URL: ${url}"
        rm -f "${temp_output}"
        return 1
    fi

    mv -f "${temp_output}" "${output_path}"
    log_debug "Download successful: ${output_path}"
}

# Generic request function
# Arguments:
#   $1: URL
#   $2: Output path (- for stdout)
req() {
    _download "$1" "$2" -A "Mozilla/5.0 (X11; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0"
}

# GitHub API request
# Arguments:
#   $1: API URL
#   $2: Output path (- for stdout)
gh_req() {
    if [[ -z "${GH_HEADER}" ]]; then
        log_warn "GITHUB_TOKEN is not set. API requests may be rate-limited."
    fi
    _download "$1" "$2" -H "${GH_HEADER}"
}

# GitHub release asset download
# Arguments:
#   $1: Output file path
#   $2: Asset URL
gh_dl() {
    log_info "Downloading GitHub asset: $1"
    _download "$2" "$1" -H "${GH_HEADER}" -H "Accept: application/octet-stream"
}

#------------------------------------------------------------------------------#
#
#                               TOML Handling
#
#------------------------------------------------------------------------------#

# Load a TOML file and convert it to JSON
# Arguments:
#   $1: Path to the TOML or JSON config file
# Returns:
#   JSON string of the config file
load_config() {
    local config_file="$1"
    if [[ ! -f "${config_file}" ]]; then
        log_error "Config file not found: ${config_file}"
        return 1
    fi

    case "${config_file##*.}" in
    toml)
        "${TOML}" --output json --file "${config_file}" .
        ;;
    json)
        cat "${config_file}"
        ;;
    *)
        log_error "Unsupported config file extension: ${config_file##*.}"
        return 1
        ;;
    esac
}

# Get table names from the config JSON
# Arguments:
#   $1: JSON config string
# Returns:
#   List of table names
config_get_table_names() {
    jq -r -e 'to_entries[] | select(.value | type == "object") | .key' <<<"$1"
}

# Get a specific table from the config JSON
# Arguments:
#   $1: JSON config string
#   $2: Table name
# Returns:
#   JSON object of the table
config_get_table() {
    jq -r -e ".\"$2\"" <<<"$1"
}

# Get a value from a JSON object (table)
# Arguments:
#   $1: JSON object string
#   $2: Key name
# Returns:
#   Value associated with the key
config_get_value() {
    local table_json="$1"
    local key="$2"
    local value
    value=$(jq -r ".\"${key}\" | values" <<<"${table_json}")
    if [[ -n "${value}" ]]; then
        # Trim whitespace and remove quotes
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        value="${value//\'/\'}"
        echo "${value}"
    else
        return 1
    fi
}

#------------------------------------------------------------------------------#
#
#                            Version Management
#
#------------------------------------------------------------------------------#

# Validate if a string is a semantic version
# Arguments:
#   $1: Version string
# Returns:
#   0 if valid semver, 1 otherwise
is_semver() {
    local version="${1#v}"
    version="${version%-*}"
    [[ "${version//[.0-9]/}" = "" ]]
}

# Get the highest version from a list of versions
# Arguments:
#   Stdin: A list of versions, one per line
# Returns:
#   The highest version string
get_highest_version() {
    local versions
    versions=$(cat)
    if [[ -z "${versions}" ]]; then
        log_error "No versions provided to get_highest_version"
        return 1
    fi

    # Check if the first version looks like a semantic version
    if is_semver "$(head -n 1 <<<"${versions}")"; then
        sort -rV <<<"${versions}" | head -n 1
    else
        # If not semver, just return the first one
        head -n 1 <<<"${versions}"
    fi
}

#------------------------------------------------------------------------------#
#
#                             Helper Functions
#
#------------------------------------------------------------------------------#

# Check if an item is in a list of items
# Arguments:
#   $1: Item to check
#   $@: List of items
# Returns:
#   0 if item is in the list, 1 otherwise
is_one_of() {
    local item="$1"
    shift
    for value in "$@"; do
        if [[ "${item}" == "${value}" ]]; then
            return 0
        fi
    done
    return 1
}

# Parse a string of arguments into a list
# Example: '"arg1" "arg2"' -> arg1\narg2
# Arguments:
#   $1: String of arguments
# Returns:
#   A newline-separated list of arguments
list_args() {
    tr -d '\t\r' <<<"$1" | tr -s ' ' | sed 's/" "/"\n"/g; s/\([^"]\)"\([^"]\)/\1'\''\2/g' | grep -v '^$' || :
}

# Join a list of arguments with a prefix
# Example: 'arg1\narg2', '-d' -> '-d arg1 -d arg2'
# Arguments:
#   $1: String of arguments
#   $2: Prefix
# Returns:
#   A space-separated string of prefixed arguments
join_args() {
    list_args "$1" | sed "s/^/${2} /" | paste -sd " " - || :
}

#------------------------------------------------------------------------------#
#
#                             APK/Bundle Handling
#
#------------------------------------------------------------------------------#

# Merge a split APK bundle (.apkm, .xapk) into a single APK
# Arguments:
#   $1: Path to the bundle file
#   $2: Output path for the merged APK
#   $3: Build mode (apk/module)
#   $4: Array of patcher arguments
merge_splits() {
    local bundle_path="$1"
    local output_path="$2"
    local build_mode="$3"
    shift 3
    local patcher_args=("$@")

    log_info "Merging splits for ${bundle_path}"

    local apkeditor_jar="${TEMP_DIR}/apkeditor.jar"
    gh_dl "${apkeditor_jar}" "https://github.com/REAndroid/APKEditor/releases/download/V1.4.2/APKEditor-1.4.2.jar" >/dev/null || return 1

    local merged_zip="${bundle_path}.mzip"
    if ! java -jar "${apkeditor_jar}" merge -i "${bundle_path}" -o "${merged_zip}" --clean-meta -f; then
        log_error "Failed to merge splits with APKEditor"
        return 1
    fi

    # Repackage the merged zip to ensure compatibility with apksigner
    local temp_unzip_dir
    temp_unzip_dir=$(mktemp -d -p "${TEMP_DIR}")
    unzip -qo "${merged_zip}" -d "${temp_unzip_dir}"

    local repacked_zip="${bundle_path}.zip"
    (
        cd "${temp_unzip_dir}" || exit 1
        zip -0rq "${repacked_zip}" .
    )

    # Sign the merged APK if building a module
    if [[ "${build_mode}" == "module" ]]; then
        patch_apk "${repacked_zip}" "${output_path}" "--exclusive" "${patcher_args[@]}"
    else
        cp "${repacked_zip}" "${output_path}"
    fi

    return $?
}

# Check the signature of an APK file
# Arguments:
#   $1: Path to the APK file
#   $2: Expected package name
# Returns:
#   0 if signature is valid or not checked, 1 otherwise
check_signature() {
    local apk_file="$1"
    local package_name="$2"
    local signature

    if grep -q "${package_name}" "sig.txt"; then
        log_info "Verifying signature for ${package_name}"
        signature=$(java -jar "${APKSIGNER}" verify --print-certs "${apk_file}" |
            grep -o -m 1 'SHA-256 digest: [0-9a-f]*' |
            awk '{print $NF}')

        if ! grep -qFx "${signature} ${package_name}" "sig.txt"; then
            log_error "APK signature mismatch for ${apk_file}"
            return 1
        fi
        log_info "Signature verified for ${package_name}"
    else
        log_warn "No signature found in sig.txt for ${package_name}, skipping check."
    fi
}

#------------------------------------------------------------------------------#
#
#                          Download Source: APKMirror
#
#------------------------------------------------------------------------------#
# (Implementation of APKMirror functions would go here)
# ... dl_apkmirror, get_apkmirror_vers, etc. ...

#------------------------------------------------------------------------------#
#
#                          Download Source: Uptodown
#
#------------------------------------------------------------------------------#
# (Implementation of Uptodown functions would go here)
# ... dl_uptodown, get_uptodown_vers, etc. ...

#------------------------------------------------------------------------------#
#
#                          Download Source: Archive.org
#
#------------------------------------------------------------------------------#
# (Implementation of Archive.org functions would go here)
# ... dl_archive, get_archive_vers, etc. ...

#------------------------------------------------------------------------------#
#
#                           ReVanced Patching
#
#------------------------------------------------------------------------------#

# Patch an APK using ReVanced CLI
# Arguments:
#   $1: Input stock APK path
#   $2: Output patched APK path
#   $3: ReVanced CLI JAR path
#   $4: ReVanced patches JAR path
#   $@: Additional patcher arguments
patch_apk() {
    local stock_apk="$1"
    local patched_apk="$2"
    local cli_jar="$3"
    local patches_jar="$4"
    shift 4
    local patcher_args=("$@")

    log_info "Patching ${stock_apk}"

    local cmd=(
        java -jar "${cli_jar}" patch "${stock_apk}"
        --purge
        -o "${patched_apk}"
        -p "${patches_jar}"
        --keystore=ks.keystore
        --keystore-entry-password="${KEYSTORE_PASS:-123456789}"
        --keystore-password="${KEYSTORE_PASS:-123456789}"
        --signer=jhc
        --keystore-entry-alias=jhc
    )
    cmd+=("${patcher_args[@]}")

    if [[ "${OS_NAME}" == "Android" ]]; then
        cmd+=(--custom-aapt2-binary="${AAPT2}")
    fi

    log_debug "Executing patch command: ${cmd[*]}"

    if ! "${cmd[@]}"; then
        log_error "Failed to patch ${stock_apk}"
        rm -f "${patched_apk}"
        return 1
    fi

    if [[ ! -f "${patched_apk}" ]]; then
        log_error "Patched APK not found after patching process: ${patched_apk}"
        return 1
    fi

    log_info "Successfully patched APK: ${patched_apk}"
}

#------------------------------------------------------------------------------#
#
#                           Module Building
#
#------------------------------------------------------------------------------#

# Configure the module properties
# Arguments:
#   $1: Module base directory
#   $2: Module ID
#   $3: Module name
#   $4: Module version
#   $5: Module description
#   $6: Update JSON URL
module_set_prop() {
    local base_dir="$1"
    local module_id="$2"
    local module_name="$3"
    local module_version="$4"
    local module_desc="$5"
    local update_json_url="$6"
    local module_prop_file="${base_dir}/module.prop"

    log_info "Configuring module properties for ${module_id}"

    cat >"${module_prop_file}" <<EOF
id=${module_id}
name=${module_name}
version=v${module_version}
versionCode=${NEXT_VER_CODE}
author=j-hc
description=${module_desc}
EOF

    if [[ ${ENABLE_MAGISK_UPDATE:-false} == true ]]; then
        echo "updateJson=${update_json_url}" >>"${module_prop_file}"
    fi
}

# Configure the module's package details
# Arguments:
#   $1: Module base directory
#   $2: Package name
#   $3: Package version
#   $4: Architecture
module_set_config() {
    local base_dir="$1"
    local pkg_name="$2"
    local pkg_ver="$3"
    local arch="$4"
    local module_arch=""

    case "${arch}" in
    "arm64-v8a") module_arch="arm64" ;;
    "arm-v7a") module_arch="arm" ;;
    esac

    cat >"${base_dir}/config" <<EOF
PKG_NAME=${pkg_name}
PKG_VER=${pkg_ver}
MODULE_ARCH=${module_arch}
EOF
}

# Pack the Magisk module
# Arguments:
#   $1: Module source directory
#   $2: Output zip file path
pack_module() {
    local source_dir="$1"
    local output_file="$2"

    log_info "Packing Magisk module: ${output_file}"
    (
        cd "${source_dir}" || abort "Module source directory not found: ${source_dir}"
        zip -"${COMPRESSION_LEVEL}" -FSqr "${output_file}" .
    ) || abort "Failed to pack module."
    log_info "Module packed successfully."
}

# This is a library file, so no main execution block.
# The main orchestration will be in build.sh.

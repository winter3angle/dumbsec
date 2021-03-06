#!/usr/bin/env bash

# Fetch latest master and generate a new content

function throw_help() {
    echo "Pelican content generation script. Theme dir assumed to have configured virtualenv within."
    echo "Usage: $0 <theme dir> <content dir> <out dir>"
    exit 1
}

function chk_dir_exists() {
    if [[ ! -d "$1" ]]; then
        echo "Invalid directory '$1' for '$2', exiting"
        exit 1
    fi
}

function chk_file_readable() {
    if [[ ! -r "$1" ]]; then
        echo "Could not read file at '$1', exiting"
        exit 1
    fi
}

function chk_app_avail() {
    which "$1"
    if [[ ! $? ]]; then
        echo "'$1' could not be found, exiting"
        exit 1
    fi
}

if [[ "$1" == "" ]]; then
    throw_help
fi

THEME_DIR="$1"
CONTENT_ROOT_DIR="$2"
CONTENT_DIR="$CONTENT_ROOT_DIR"
OUTPUT_DIR="$3"
VENV_DIR="$THEME_DIR/venv"
PELICAN_CONF_FILE="$CONTENT_ROOT_DIR/pelicanconf.py"
VENV_ACT_FILE="$VENV_DIR/bin/activate"

chk_dir_exists "$THEME_DIR" "theme dir"
chk_dir_exists "$CONTENT_ROOT_DIR" "content root dir"
chk_dir_exists "$CONTENT_DIR" "content dir"
chk_dir_exists "$OUTPUT_DIR" "output dir"
chk_dir_exists "$VENV_DIR" "pelican virtualenv"
chk_file_readable "$PELICAN_CONF_FILE" "pelican config"
chk_file_readable "$VENV_ACT_FILE" "virtualenv activation file"
chk_app_avail git
chk_app_avail pelican

cd "$CONTENT_ROOT_DIR"
git fetch origin master
git reset --hard FETCH_HEAD
source "$VENV_ACT_FILE"
python3 -m pelican -t "$THEME_DIR" -o "$OUTPUT_DIR" --delete-output-directory --ignore-cache -s "$PELICAN_CONF_FILE" "$CONTENT_DIR"
deactivate

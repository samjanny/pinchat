#!/bin/bash
#
# PinChat Extension Icon Generator
# =================================
#
# Generates PNG icons in multiple sizes from the source SVG file
# for both Chrome and Firefox browser extensions.
#
# REQUIREMENTS:
#   One of the following tools must be installed:
#   - ImageMagick (convert command)
#   - Inkscape
#
#   Install on Ubuntu/Debian:  sudo apt install imagemagick
#   Install on macOS:          brew install imagemagick
#
# USAGE:
#   cd extensions/
#   ./generate-icons.sh
#
# OUTPUT:
#   Creates PNG icons in the following sizes: 16x16, 32x32, 48x48, 128x128
#   Files are placed in:
#     - chrome/icons/icon-{size}.png
#     - firefox/icons/icon-{size}.png
#
# SOURCE:
#   The source SVG file is: chrome/icons/icon.svg
#

SVG_FILE="chrome/icons/icon.svg"
CHROME_ICONS="chrome/icons"
FIREFOX_ICONS="firefox/icons"

SIZES="16 32 48 128"

# Check for conversion tools
if command -v convert &> /dev/null; then
    echo "Using ImageMagick..."
    for size in $SIZES; do
        convert -background none -resize ${size}x${size} "$SVG_FILE" "${CHROME_ICONS}/icon-${size}.png"
        convert -background none -resize ${size}x${size} "$SVG_FILE" "${FIREFOX_ICONS}/icon-${size}.png"
        echo "Generated ${size}x${size} icons"
    done
elif command -v inkscape &> /dev/null; then
    echo "Using Inkscape..."
    for size in $SIZES; do
        inkscape -w $size -h $size "$SVG_FILE" -o "${CHROME_ICONS}/icon-${size}.png"
        inkscape -w $size -h $size "$SVG_FILE" -o "${FIREFOX_ICONS}/icon-${size}.png"
        echo "Generated ${size}x${size} icons"
    done
else
    echo "No conversion tool found. Please install ImageMagick or Inkscape."
    echo "On Ubuntu/Debian: sudo apt install imagemagick"
    echo "On macOS: brew install imagemagick"
    echo ""
    echo "Or manually convert the SVG at: $SVG_FILE"
    echo "To PNG files at sizes: $SIZES"
    exit 1
fi

echo "Done! Icons generated successfully."

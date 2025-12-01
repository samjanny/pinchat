#!/bin/bash
# Generate PNG icons from SVG
# Requires: ImageMagick (convert) or inkscape

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

#!/bin/bash

# Manual NVD data download script
# Downloads the NVD JSON feeds directly and converts them for dependency-check

set -e

echo "Manual NVD Data Download Script"
echo "================================"

DATA_DIR=~/.gradle/dependency-check-data/11.0
TEMP_DIR=/tmp/nvd-download-$$

# Create directories
mkdir -p "$DATA_DIR"
mkdir -p "$TEMP_DIR"

echo "Working directory: $TEMP_DIR"
echo "Target directory: $DATA_DIR"

# Function to download a feed
download_feed() {
    local year=$1
    local url="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-${year}.json.gz"
    local meta_url="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-${year}.meta"

    echo -n "Downloading CVE-${year}... "

    # Download meta file
    curl -s "$meta_url" -o "$TEMP_DIR/nvdcve-2.0-${year}.meta"

    # Download data file
    if curl -s "$url" -o "$TEMP_DIR/nvdcve-2.0-${year}.json.gz"; then
        echo "✓"
        return 0
    else
        echo "✗"
        return 1
    fi
}

# Download recent and modified feeds first
echo ""
echo "Downloading critical feeds..."
download_feed "modified"
download_feed "recent"

# Download year feeds
echo ""
echo "Downloading yearly feeds (this will take a few minutes)..."
for year in 2025 2024 2023 2022 2021 2020; do
    download_feed "$year"
done

# Extract all files
echo ""
echo "Extracting files..."
cd "$TEMP_DIR"
for file in *.json.gz; do
    if [ -f "$file" ]; then
        echo -n "Extracting $file... "
        gunzip -f "$file"
        echo "✓"
    fi
done

# Now download CPE data
echo ""
echo "Downloading CPE match data (large file ~531MB)..."
CPE_URL="https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz"
if curl -# "$CPE_URL" -o "$TEMP_DIR/nvdcpematch-2.0.tar.gz"; then
    echo "Extracting CPE data..."
    tar -xzf "$TEMP_DIR/nvdcpematch-2.0.tar.gz"
    echo "✓ CPE data downloaded"
else
    echo "✗ Failed to download CPE data"
fi

# Move to data directory
echo ""
echo "Moving data to dependency-check directory..."
cp -f "$TEMP_DIR"/*.json "$DATA_DIR/" 2>/dev/null || true
cp -f "$TEMP_DIR"/*.meta "$DATA_DIR/" 2>/dev/null || true

# Clean up
rm -rf "$TEMP_DIR"

echo ""
echo "Download complete!"
echo "Data location: $DATA_DIR"
ls -lh "$DATA_DIR"/*.json 2>/dev/null | head -5

echo ""
echo "Note: The dependency-check plugin may still need to process this data."
echo "Run: ./gradlew dependencyCheckAnalyze"

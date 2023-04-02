#!/bin/bash

# Replace YOUR_API_KEY with your VirusTotal API key
API_KEY="YOUR_API_KEY"

# Get the attachment file path from the command line arguments
attachment="$1"

# Calculate the file's MD5 hash
md5=$(md5sum "$attachment" | cut -d ' ' -f 1)

# Query VirusTotal's API to check if the file is a phishing file
response=$(curl -s "https://www.virustotal.com/vtapi/v2/file/report?apikey=$API_KEY&resource=$md5")
result=$(echo "$response" | jq '.scans')

# Check if any of the antivirus engines have identified the file as a phishing file
if echo "$result" | grep -q 'true'; then
  echo "WARNING: The file $attachment may be a phishing file"
  exit 1
else
  echo "The file $attachment appears to be legitimate"
  exit 0
fi

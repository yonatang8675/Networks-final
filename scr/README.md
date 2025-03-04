# PCAPNG Analysis

This Python script analyzes PCAPNG files and generates graphs to visualize network traffic using **pyshark** and **matplotlib**. In addition, it supports decrypting TLS traffic if a corresponding TLS Key Log file is provided.

---

## Overview

The script performs the following tasks:

- **PCAPNG Analysis:**  
  Reads each PCAPNG file with a TLS key log file and extracts important data such as:
    - **Packet Sizes:** A list of sizes for each captured packet.
    - **Time Differences:** The inter-arrival times between consecutive packets.
    - **Flows:** Identification of flows based on IP version, source and destination IPs, ports, and transport protocol. For each flow, it tracks the packet count and total bytes.
    - **Protocol Counts:** Counting the occurrence of different protocols.
    - **TLS Data:** The script attempts to decrypt TLS traffic, collecting record length, version, and content types.

- **Statistical Calculations:**  
  Computes various statistics for packet sizes (average, median, minimum, maximum, standard deviation) and for the time differences between packets.

- **Graph Generation:**  
  Generates and saves graphs as image files in an output directory. The graphs include:
    1. **Scatter Plots** for Packet Sizes and Time Differences.
    2. **Bar Charts** showing counts of protocols, TCP flags, TLS versions, TLS content types, and flow counts.
    3. **Subplots:** displaying statistics for packet sizes, TCP window sizes, TLS record lengths, TTL/HLim, and inter-packet time differences.
---

## File Structure

- **`main.py`**  
  Contains the main script that:
    - Reads a list of PCAPNG file paths from `Captures_files.txt`
    - Reads a list of TLS key log file paths from `TLS_keys_files.txt`
    - Ensures there is a matching number of entries in both files
    - Processes each PCAPNG file and its matching TLS key file via the process_capture function
    - Generates and saves the graphs using the plot_results function

- **`Captures_files.txt`:** A text file listing the paths to the PCAPNG files to be analyzed, one per line.
- **`TLS_keys_files.txt`:**
  A text file listing the paths to TLS key log files, one per line, corresponding to the files in Captures_files.txt.
- **`output/`:** The directory where all generated graph images are saved.

---

## Dependencies

The script uses the following Python libraries:

- **pyshark** - For parsing and analyzing PCAPNG files.
- **matplotlib** - For generating graphs and plots.
- **statistics** - For computing statistical measures.
- **nest_asyncio** - For handling async event loops (useful in Jupyter Notebook environments).
- **os** - For file and directory management.

Install the required third-party libraries with:

```sh
pip install -r requirements.txt
# PCAPNG Analysis

This Python script analyzes PCAPNG files and generates graphs to visualize network traffic using **pyshark** and **matplotlib**.

---

## Overview

The script performs the following tasks:

- **PCAPNG Analysis:**  
  Reads each PCAPNG file and extracts important data such as:
    - **Packet Sizes:** A list of sizes for each captured packet.
    - **Time Differences:** The inter-arrival times between consecutive packets.
    - **Flows:** Identification of flows based on IP version, source and destination IPs, ports, and transport protocol. For each flow, it tracks the packet count and total bytes.
    - **Protocol Counts:** Counting the occurrence of different protocols.

- **Statistical Calculations:**  
  Computes various statistics for packet sizes (average, median, minimum, maximum, standard deviation) and for the time differences between packets.

- **Graph Generation:**  
  Generates and saves graphs as image files in an output directory. The graphs include:
    1. **Packet Size Distribution:**  
       A histogram of packet sizes for each PCAPNG file.
    2. **Time Difference Between Packets:**  
       A boxplot of the time intervals between consecutive packets.
    3. **Protocols Count:**  
       A bar chart comparing protocol usage across files.
    4. **Flow Count:**  
       A bar chart showing the number of flows detected in each file.
    5. **Average Packet Size:**  
       A bar chart displaying the average packet size per file.
    6. **Average Time Difference Between Packets:**  
       A bar chart representing the average time difference between consecutive packets for each file.

---

## File Structure

- **`main.py`**  
  Contains the main script that:
    - Reads a list of PCAPNG file paths from `pcapng_files.txt`
    - Analyzes each file using the `analyze_pcapng` function
    - Generates and saves the graphs using the `plot_results` function

- **`pcapng_files.txt`**  
  A text file listing the paths to the PCAPNG files to be analyzed, one per line.

- **`output/`**  
  The directory where all generated graph images are saved.

---

## Dependencies

The script uses the following Python libraries:

- **pyshark** – For parsing and analyzing PCAPNG files.
- **matplotlib** – For generating graphs and plots.
- **statistics** – For computing statistical measures.
- **os** – For file and directory management.

Install the required third-party libraries with:

```sh
pip install -r requirements.txt
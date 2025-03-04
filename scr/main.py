import pyshark
import matplotlib.pyplot as plt
import statistics
import os

# for working with jupiter
import nest_asyncio
nest_asyncio.apply()

debug_level = False


def process_capture(capture_file, tls_key_file=None):
    """
    Processes a PCAPNG file using its TLS key file by analyzing the capture and computing statistics.

    Parameters:
        capture_file (str): Path to the PCAPNG capture file.
        tls_key_file (str): Path to the TLS key file for decryption.

    Returns:
        dict: A dictionary containing extracted data with computed statistics.
    """
    data = analyze_capture(capture_file, tls_key_file)
    data = add_statistics(data)
    return data


def analyze_capture(capture_file, tls_key_file=None):
    """
    Analyze a PCAPNG file using a TLS key file for optional TLS decryption.

    Parameters:
        capture_file (str): Path to the PCAPNG file.
        tls_key_file (str): Path to the TLS key file.

    Returns:
        dict: A dictionary with the collected network data.
    """

    if not os.path.isfile(capture_file):
        raise ValueError(f'The given pcapng file "{capture_file}" does not exist.')

    if tls_key_file is not None and not os.path.isfile(tls_key_file):
        raise ValueError(f'The given TLS key file "{tls_key_file}" does not exist.')

    print(f'Analyzing {capture_file} with TLS key file: {tls_key_file}')

    override_prefs = {}
    if tls_key_file is not None:
        override_prefs['tls.keylog_file'] = tls_key_file
    with pyshark.FileCapture(capture_file, use_json=True,
                             display_filter="ip or ipv6 or tcp or tls or udp or quic or http or http3 or dns",
                             override_prefs=override_prefs) as capture:
        data = {
            'TTL_HLim values': [],
            'packet_sizes': [],
            'time_diff': [],
            'flows': {},
            'protocol_counts': {},
            'tls_record_length': [],
            'tls_content_type': {},
            'tls_version': {},
            'tcp_window_sizes': [],
            'tcp_flags': {},
        }
        arrival_times = []

        for packet in capture:
            try:

                # IP layer: IPv4 and IPv6
                if hasattr(packet, 'ip'):
                    ip_version = 'IPv4'
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    ttl = int(packet.ip.ttl)
                    data['TTL_HLim values'].append(ttl)

                elif hasattr(packet, 'ipv6'):
                    ip_version = 'IPv6'
                    src_ip = packet.ipv6.src
                    dst_ip = packet.ipv6.dst
                    hlim = int(packet.ipv6.hlim)
                    data['TTL_HLim values'].append(hlim)

                else:  # no ip layer
                    continue

                # Transport layer
                if hasattr(packet, 'quic'):
                    transport = 'QUIC'

                elif hasattr(packet, 'tcp'):
                    transport = 'TCP'

                    # TCP flags
                    if hasattr(packet.tcp, 'flags'):
                        try:
                            tcp_flags = parse_tcp_flags(packet.tcp.flags)
                        except Exception as e:
                            if debug_level:
                                print(e)
                            continue

                        # add new key if needed
                        if tcp_flags not in data['tcp_flags'].keys():
                            data['tcp_flags'][tcp_flags] = 0
                        data['tcp_flags'][tcp_flags] += 1

                    # TCP window size
                    if hasattr(packet.tcp, 'window_size_value'):
                        window_size = int(packet.tcp.window_size_value)
                        data['tcp_window_sizes'].append(window_size)

                elif hasattr(packet, 'udp'):
                    transport = 'UDP'

                else:  # no known transport layer
                    continue

                # Count protocols
                if transport not in data['protocol_counts']:
                    data['protocol_counts'][transport] = 0
                data['protocol_counts'][transport] += 1

                # TLS
                if hasattr(packet, 'tls') or hasattr(packet, 'ssl'):
                    tls_layer = packet.tls if hasattr(packet, 'tls') else packet.ssl
                    if hasattr(tls_layer, 'data'):
                        try:
                            # parse the TLS header
                            content_type, version, record_length = parse_tls_header(tls_layer.data)
                        except Exception as e:
                            if debug_level:
                                print(e)
                            continue

                        # add keys in needed
                        if content_type not in data['tls_content_type'].keys():
                            data['tls_content_type'][content_type] = 0
                        if version not in data['tls_version'].keys():
                            data['tls_version'][version] = 0

                        # update data
                        data['tls_content_type'][content_type] += 1
                        data['tls_version'][version] += 1
                        data['tls_record_length'].append(record_length)

                    # add keys in needed
                    if 'TLS' not in data['protocol_counts']:
                        data['protocol_counts']['TLS'] = 0
                    data['protocol_counts']['TLS'] += 1

                # Handle DNS protocol counting.
                if hasattr(packet, 'dns'):
                    # add keys in needed
                    if 'DNS' not in data['protocol_counts']:
                        data['protocol_counts']['DNS'] = 0
                    data['protocol_counts']['DNS'] += 1

                # Flow: (ip version, src ip, dst ip, src port, dst port, transport)
                if hasattr(packet, transport.lower()):
                    layer = getattr(packet, transport.lower())
                    src_port = getattr(layer, 'srcport', 'unknown')
                    dst_port = getattr(layer, 'dstport', 'unknown')
                else:
                    src_port = 'unknown'
                    dst_port = 'unknown'

                # Packet size
                pkt_size = int(packet.length)
                data['packet_sizes'].append(pkt_size)

                # Packet time
                sniff_time = packet.sniff_time
                arrival_times.append(sniff_time)

                # update flow data
                flow_key = (ip_version, src_ip, dst_ip, src_port, dst_port, transport)
                if flow_key not in data['flows']:
                    data['flows'][flow_key] = {'packet_count': 0, 'byte_count': 0}
                data['flows'][flow_key]['packet_count'] += 1
                data['flows'][flow_key]['byte_count'] += pkt_size

            except AttributeError as e:
                if debug_level:
                    print(e)
                continue

    # Calculate inter-packet time differences.
    if len(arrival_times) > 1:
        arrival_times.sort()
        data['time_diff'] = []
        for i in range(len(arrival_times) - 1):
            diff = (arrival_times[i + 1] - arrival_times[i]).total_seconds()
            data['time_diff'].append(diff)

    return data


def add_statistics(data):
    """
    Compute and add statistical metrics to the data.
    This function calculates various statistics from the extracted data.
    The computed values are stored in a new 'statistics' key in the input dictionary.
    Parameters:
        data (dict): A dictionary containing lists of network metrics.
    Returns:
        dict: The updated data dictionary with the computed statistics.
    """

    data['statistics'] = {}

    # TLS Record Length Statistics
    if data['tls_record_length']:
        record_lengths = data['tls_record_length']
        try:
            data['statistics']['Average Record Length'] = statistics.mean(record_lengths)
            data['statistics']['Median Record Length'] = statistics.median(record_lengths)
            data['statistics']['Max Record Length'] = max(record_lengths)
            data['statistics']['Min Record Length'] = min(record_lengths)
        except ArithmeticError as e:
            if debug_level:
                print(e)
            data['statistics']['Average Record Length'] = 0
            data['statistics']['Median Record Length'] = 0
            data['statistics']['Max Record Length'] = 0
            data['statistics']['Min Record Length'] = 0

    # Packet Size Statistics
    pkt_sizes = data['packet_sizes']
    if pkt_sizes:
        data['statistics']['Average Packet Size'] = statistics.mean(pkt_sizes)
        data['statistics']['Median Packet Size'] = statistics.median(pkt_sizes)
        data['statistics']['Max Packet Size'] = max(pkt_sizes)
        data['statistics']['STD Packet Size'] = statistics.pstdev(pkt_sizes) if len(pkt_sizes) > 1 else 0.0
    else:
        data['statistics']['Average Packet Size'] = 0
        data['statistics']['Median Packet Size'] = 0
        data['statistics']['Max Packet Size'] = 0
        data['statistics']['STD Packet Size'] = 0

    # TTL and HLim Statistics
    ttls_hlims = data['TTL_HLim values']
    if ttls_hlims:
        data['statistics']['Average TTL_HLim'] = statistics.mean(ttls_hlims)
        data['statistics']['Median TTL_HLim'] = statistics.median(ttls_hlims)
        data['statistics']['Max TTL_HLim'] = max(ttls_hlims)
        data['statistics']['STD TTL_HLim'] = statistics.pstdev(ttls_hlims) if len(ttls_hlims) > 1 else 0.0
    else:
        data['statistics']['Average TTL_HLim'] = 0
        data['statistics']['Median TTL_HLim'] = 0
        data['statistics']['Max TTL_HLim'] = 0
        data['statistics']['STD TTL_HLim'] = 0

    # TCP Window Size Statistics
    window_sizes = data['tcp_window_sizes']
    if window_sizes:
        data['statistics']['Average Window Size'] = statistics.mean(window_sizes)
        data['statistics']['Median Window Size'] = statistics.median(window_sizes)
        data['statistics']['Max Window Size'] = max(window_sizes)
        data['statistics']['STD Window Size'] = statistics.pstdev(window_sizes) if len(window_sizes) > 1 else 0.0
    else:
        data['statistics']['Average Window Size'] = 0
        data['statistics']['Median Window Size'] = 0
        data['statistics']['Max Window Size'] = 0
        data['statistics']['STD Window Size'] = 0

    # Time Difference Statistics
    time_diff = data['time_diff']
    if time_diff:
        data['statistics']['Average Time Difference Between Packets'] = statistics.mean(time_diff)
        data['statistics']['Median Time Difference Between Packets'] = statistics.median(time_diff)
        data['statistics']['STD Time Difference Between Packets'] = \
            statistics.pstdev(time_diff) if len(time_diff) > 1 else 0.0
    else:
        data['statistics']['Average Time Difference Between Packets'] = 0
        data['statistics']['Median Time Difference Between Packets'] = 0
        data['statistics']['STD Time Difference Between Packets'] = 0

    return data


def parse_tcp_flags(flags):
    """
    Convert a hexadecimal TCP flags value to a description.
    Parameters:
        flags (str): A hexadecimal string representing TCP flags.
    Returns:
        str: A description of the TCP flags.
    Raises:
        KeyError: If the provided flag value is not recognized.
    """

    tcp_flags_map = {
        '0x0000': 'No Flags',
        '0x0001': 'FIN',
        '0x0002': 'SYN',
        '0x0003': 'FIN+SYN',
        '0x0004': 'RST',
        '0x0005': 'RST+FIN',
        '0x0008': 'PSH',
        '0x0009': 'FIN+PSH',
        '0x000A': 'SYN+PSH',
        '0x000C': 'RST+PSH',
        '0x0010': 'ACK',
        '0x0011': 'FIN+ACK',
        '0x0012': 'SYN+ACK',
        '0x0014': 'RST+ACK',
        '0x0018': 'PSH+ACK'
    }

    try:
        flags = tcp_flags_map[flags]
    except KeyError:
        raise KeyError(f'Can\'t parse TCP flags from data: {flags}')

    return flags


def parse_tls_header(tls_data):
    """
    Parse a TLS header from a colon-separated hex string.
    Splits the input into components and extracts the values.
    Parameters:
        tls_data (str): A colon-separated hex string representing the TLS header.
    Returns:
        tuple: (content_type, version, record_length)
    Raises:
        KeyError: If the header is too short or contains unknown values.
    """
    hex_bytes = tls_data.split(':')

    # smaller then tls header
    if len(hex_bytes) < 5:
        raise KeyError(f'Can\'t parse TLS header - too small')

    # get header fields
    content_type = hex_bytes[0]
    version = f'{hex_bytes[1]} {hex_bytes[2]}'
    record_length = int(f'{hex_bytes[3]}{hex_bytes[4]}', 16)

    content_types_map = {'14': 'Change Cipher Spec',
                         '15': 'Alert',
                         '16': 'Handshake',
                         '17': 'Application Data'}

    versions_map = {'03 00': 'SSL 3.0',
                    '03 01': 'TLS 1.0',
                    '03 02': 'TLS 1.1',
                    '03 03': 'TLS 1.2',
                    '03 04': 'TLS 1.3'}

    try:
        content_type = content_types_map[content_type]
        version = versions_map[version]
    except KeyError:
        raise KeyError(f'Can\'t parse TLS header: {hex_bytes[0:6]}')

    return content_type, version, record_length


def plot_results(analyzing_results, file_names, output_dir='output'):
    """
    Generate and save plots based on the analysis results of PCAPNG files.
    This function creates the output directory if needed, sets a fixed figure size,
    and then calls various helper plotting functions to generate and save charts.
    Parameters:
        analyzing_results (list): A list of dictionaries containing network analysis data.
        file_names (list): A list of file names corresponding to each analysis result.
        output_dir (str, optional): The directory where the plots will be saved.
    Returns:
        None
    """

    os.makedirs(output_dir, exist_ok=True)
    plot_fig_size = (24, 12)

    # bars plot for Flow Count
    flow_counts = [len(res['flows']) for res in analyzing_results]
    plot_bars(plot_fig_size, flow_counts, file_names, output_dir, 'Flow Count', 'Count')

    # scatter plot for Packet Sizes
    plot_scatter(plot_fig_size, analyzing_results, 'packet_sizes', file_names, output_dir,
                 'Packet Sizes', 'Packet Count')

    # scatter plot for Time Difference Between Packets
    plot_scatter(plot_fig_size, analyzing_results, 'time_diff', file_names, output_dir,
                 'Time Difference Between Packets', 'Time (sec)')

    # multi-bars plot for Protocols Count
    plot_multi_bars(plot_fig_size, analyzing_results, 'protocol_counts', file_names, output_dir,
              'Protocols Count', 'Packet Count')

    # multi-bars plot for TCP Flags Count
    plot_multi_bars(plot_fig_size, analyzing_results, 'tcp_flags', file_names, output_dir,
              'TCP Flags Count', 'Packet Count')

    # multi-bars plot for TLS Content Type Count
    plot_multi_bars(plot_fig_size, analyzing_results, 'tls_content_type', file_names, output_dir,
              'TLS Content Type Count', 'Packet Count')

    # multi-bars plot for TLS Version Count
    plot_multi_bars(plot_fig_size, analyzing_results, 'tls_version', file_names, output_dir,
              'TLS Version Count', 'Packet Count')

    # bars sub-plot for TLS Record Length Statistics
    plot_group = 'Statistics - TLS Record Length'
    plot_keys = ['Average Record Length', 'Median Record Length', 'Max Record Length', 'Min Record Length']
    plot_statistics_subplot_bars(plot_fig_size, analyzing_results, plot_group, plot_keys, file_names, output_dir)

    # bars sub-plot for Packet Size Statistics
    plot_group = 'Statistics - Packet Size'
    plot_keys = ['Average Packet Size', 'Median Packet Size', 'Max Packet Size', 'STD Packet Size']
    plot_statistics_subplot_bars(plot_fig_size, analyzing_results, plot_group, plot_keys, file_names, output_dir)

    # bars sub-plot for Time Difference Between Packets Statistics
    plot_group = 'Statistics - Time Difference Between Packets'
    plot_keys = ['Average Time Difference Between Packets', 'Median Time Difference Between Packets',
                 'STD Time Difference Between Packets']
    plot_statistics_subplot_bars(plot_fig_size, analyzing_results, plot_group, plot_keys, file_names, output_dir)

    # bars sub-plot for TTL and HLim Statistics
    plot_group = 'Statistics - TTL_HLim'
    plot_keys = ['Average TTL_HLim', 'Median TTL_HLim',  'Max TTL_HLim', 'STD TTL_HLim']
    plot_statistics_subplot_bars(plot_fig_size, analyzing_results, plot_group, plot_keys, file_names, output_dir)

    # bars sub-plot for TCP Window Size Statistics
    plot_group = 'Statistics - TCP Window Size'
    plot_keys = ['Average Window Size', 'Median Window Size', 'Max Window Size', 'STD Window Size']
    plot_statistics_subplot_bars(plot_fig_size, analyzing_results, plot_group, plot_keys, file_names, output_dir)


def plot_bars(plot_fig_size, plot_list, file_names, output_dir, title, ylabel):
    """
    Generate and save a bar chart.

    Parameters:
        plot_fig_size (tuple): Figure size (width, height).
        plot_list (list): Heights for each bar.
        file_names (list): Labels for the bars (x-axis).
        output_dir (str): Directory to save the plot.
        title (str): Chart title (also used as the filename).
        ylabel (str): Label for the y-axis.

    Returns:
        None
    """
    plt.figure(figsize=plot_fig_size)
    bars = plt.bar(file_names, plot_list, alpha=0.6, label=ylabel)
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height, f'{height:.0f}', ha='center', va='bottom', fontsize=10)
    plt.xticks(rotation=10)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.legend()
    plt.savefig(os.path.join(output_dir, f'{title}.png'), dpi=300)
    plt.close()


def plot_scatter(plot_fig_size, analyzing_results, plot_key, file_names, output_dir, title, ylabel):
    """
    Generate and save a scatter plot for a specific analysis key across multiple files.

    Parameters:
        plot_fig_size (tuple): Figure dimensions (width, height).
        analyzing_results (list): List of analysis result dictionaries.
        plot_key (str): Dictionary key to extract values for plotting.
        file_names (list): List of file names for labeling the x-axis.
        output_dir (str): Directory where the plot image will be saved.
        title (str): Title of the plot.
        ylabel (str): Label for the y-axis.

    Returns:
        None
    """
    plt.figure(figsize=plot_fig_size)

    for i, file in enumerate(file_names):
        y_values = analyzing_results[i][plot_key]
        x_values = [i] * len(y_values)
        plt.scatter(x_values, y_values, alpha=0.1, s=10)

    plt.xticks(range(len(file_names)), file_names, rotation=10)
    plt.xlabel("Files")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.savefig(os.path.join(output_dir, f'{title}.png'), dpi=300)
    plt.close()


def plot_multi_bars(plot_fig_size, analyzing_results, plot_key, file_names, output_dir, title, ylabel):
    plt.figure(figsize=plot_fig_size)
    flags = set()
    for result in analyzing_results:
        flags.update(result[plot_key].keys())
    flags = list(flags)
    bar_width = 0.15
    x_line = range(len(flags))
    for i, file in enumerate(file_names):
        counts = []
        for flag in flags:
            counts.append(analyzing_results[i][plot_key].get(flag, 0))
        positions = [pos + (i * bar_width) for pos in x_line]
        bars = plt.bar(positions, counts, bar_width, label=file)
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, height, f'{height:.0f}', ha='center', va='bottom', fontsize=10)
    label_positions = [pos + (bar_width * (len(file_names) / 2)) for pos in x_line]
    plt.xticks(label_positions, flags)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.legend()
    plt.savefig(os.path.join(output_dir, f'{title}.png'), dpi=300)
    plt.close()


def plot_statistics_subplot_bars(plot_fig_size, analyzing_results, plot_group, plot_keys, file_names, output_dir):
    """
    Generate and save a 2x2 grid of bar charts for selected statistical metrics.

    For each key in plot_keys, this function extracts values from the 'statistics' dictionary
    of each analysis result and plots them as a bar chart in a subplot.

    Parameters:
        plot_fig_size (tuple): Figure dimensions (width, height).
        analyzing_results (list): List of analysis result dictionaries containing statistics.
        plot_group (str): Title for the group of plots and filename for the saved image.
        plot_keys (list): List of statistic keys to plot.
        file_names (list): List of file names for labeling the x-axis.
        output_dir (str): Directory where the plot image will be saved.

    Returns:
        None
    """
    plt.figure(figsize=plot_fig_size)
    for idx, key in enumerate(plot_keys):
        plt.subplot(2, 2, idx + 1)
        current_values = [res['statistics'].get(key, 0) for res in analyzing_results]
        plt.bar(file_names, current_values, alpha=0.7)
        for j, value in enumerate(current_values):
            plt.text(j, value, f'{value:.5f}', ha='center', va='bottom', fontsize=10)
        plt.xticks(rotation=10)
        plt.title(key)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f'{plot_group}.png'), dpi=300)
    plt.close()


def main():

    # open input files
    try:
        with open('Captures_files.txt') as f:
            captures_files = f.read().splitlines()

        with open('TLS_keys_files.txt') as f:
            tls_keys_files = f.read().splitlines()

        if len(captures_files) != len(tls_keys_files):
            raise ValueError('Number of captures_files and tls_keys_files do not match')

    except Exception as e:
        if debug_level:
            print(e)
        return

    # analyze the captures
    analyzing_results = []
    for i in range(len(captures_files)):
        try:
            results = process_capture(captures_files[i], tls_keys_files[i])
            analyzing_results.append(results)

        except Exception as e:
            if debug_level:
                print(e)
            continue

    # plot the results
    captures_names = [path.split('/')[-1] for path in captures_files]
    try:
        plot_results(analyzing_results, captures_names)
    except Exception as e:
        if debug_level:
            print(f"Error plotting results: {e}")


if __name__ == '__main__':

    main()

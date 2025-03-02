import pyshark
import matplotlib.pyplot as plt
import statistics
import os

def get_tls_keylog_file(pcapng_file):
    """
    Return the path to the TLS key log file in the TLS_keys directory
    based on the .pcapng filename. Adjust logic as needed if your
    naming scheme differs.
    """
    base_name = os.path.basename(pcapng_file).lower()
    if 'chrome' in base_name:
        return 'TLS_keys/ChromeTLS.log'
    elif 'microsoftedge' in base_name:
        return 'TLS_keys/MicrosoftEdgeTLS.log'
    elif 'spotify' in base_name:
        return 'TLS_keys/SpotifyTLS.log'
    elif 'youtube' in base_name:
        return 'TLS_keys/YoutubeTLS.log'
    elif 'zoom' in base_name:
        return 'TLS_keys/ZoomTLS.log'
    else:
        return None


def analyze_pcapng(pcapng_file, tls_key_file=None):

    """
    Analyze the given pcapng file. If a matching TLS key file is found,
    set the SSLKEYLOGFILE environment variable to decrypt TLS traffic.
    """
    if tls_key_file and os.path.exists(tls_key_file):
        print(f'Analyzing {pcapng_file} with TLS key file: {tls_key_file}')
        capture = pyshark.FileCapture(
            pcapng_file,
            keep_packets=False,
            use_json=True,
            override_prefs={'tls.keylog_file': tls_key_file},
            include_raw=False,
            only_summaries=False,
            display_filter="ip or ipv6 or tcp or tls or udp or "
                           "tcp.flags or tcp.analysis or "
                           "tcp.port==443 or tcp.port==80 or udp.port==443 or "
                           "quic or http or http3 or dns"
        )
    else:
        print(f'Analyzing {pcapng_file} (No TLS key file found)')
        capture = pyshark.FileCapture(
            pcapng_file,
            keep_packets=False,
            use_json=True,
            include_raw=False,
            only_summaries=False
        )
    data = {
        'ttl values': [],
        'packet_sizes': [],
        'time_diff': [],
        'flows': {},
        'protocol_counts': {},
        'statistics': {},
        # TLS header field values
        'tls_record_length': [],
        'tls_content_type': [],
        'tls_version': [],
        # IP header field values (we'll collect IP ID for IPv4)
        'ip_ids': [],
        # TCP header field values
        'tcp_window_sizes': [],
        'tcp_flags': [],
    }

    arrival_times = []

    for packet in capture:
        try:
            # Packet size
            pkt_size = int(packet.length)
            data['packet_sizes'].append(pkt_size)

            # Packet time
            sniff_time = packet.sniff_time
            arrival_times.append(sniff_time)

            # IP layer: IPv4 and IPv6; also collect IP ID if available for IPv4.
            if hasattr(packet, 'ip'):
                ip_version = 'IPv4'
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                ttl = int(packet.ip.ttl)
                data['ttl values'].append(ttl)
                if hasattr(packet.ip, 'id'):
                    try:
                        ip_id = int(packet.ip.id)
                        data['ip_ids'].append(ip_id)
                    except Exception:
                        pass
            elif hasattr(packet, 'ipv6'):
                ip_version = 'IPv6'
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
                ttl = int(packet.ipv6.ttl)
                data['ttl values'].append(ttl)
            else:
                continue

            # Transport layer detection and TCP-specific processing
            if hasattr(packet, 'quic'):
                transport = 'QUIC'
            elif hasattr(packet, 'tcp'):
                transport = 'TCP'
                # TCP flags
                if hasattr(packet.tcp, 'flags'):
                    data['tcp_flags'].append(packet.tcp.flags)
                # TCP window size
                if hasattr(packet.tcp, 'window_size_value'):
                    try:
                        window_size = int(packet.tcp.window_size_value)
                        data['tcp_window_sizes'].append(window_size)
                    except Exception:
                        pass
            elif hasattr(packet, 'udp'):
                transport = 'UDP'
            else:
                transport = packet.highest_layer

            # Count protocols
            if transport not in data['protocol_counts']:
                data['protocol_counts'][transport] = 0
            data['protocol_counts'][transport] += 1

            # Inside your packet loop
            if hasattr(packet, 'tls') or hasattr(packet, 'ssl'):
                tls_layer = packet.tls if hasattr(packet, 'tls') else packet.ssl
                if hasattr(tls_layer, 'record_content_type'):
                    data['tls_content_type'].append(tls_layer.record_content_type)
                if hasattr(tls_layer, 'record_version'):
                    data['tls_version'].append(tls_layer.record_version)
                if hasattr(tls_layer, 'record_length'):
                    try:
                        rec_len = int(tls_layer.record_length)
                        data['tls_record_length'].append(rec_len)
                    except Exception:
                        pass

            # Handle DNS protocol counting.
            if hasattr(packet, 'dns'):
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

            flow_key = (ip_version, src_ip, dst_ip, src_port, dst_port, transport)
            if flow_key not in data['flows']:
                data['flows'][flow_key] = {'packet_count': 0, 'byte_count': 0}
            data['flows'][flow_key]['packet_count'] += 1
            data['flows'][flow_key]['byte_count'] += pkt_size

        except AttributeError:
            continue

    capture.close()

    # Calculate inter-packet time differences.
    if len(arrival_times) > 1:
        arrival_times.sort()
        data['time_diff'] = []
        for i in range(len(arrival_times) - 1):
            diff = (arrival_times[i + 1] - arrival_times[i]).total_seconds()
            data['time_diff'].append(diff)

    # --- Compute TLS Record Length Statistics ---
    if data['tls_record_length']:
        record_lengths = data['tls_record_length']
        try:
            data['statistics']['Average Record Length'] = statistics.mean(record_lengths)
            data['statistics']['Median Record Length'] = statistics.median(record_lengths)
            data['statistics']['Max Record Length'] = max(record_lengths)
            data['statistics']['Min Record Length'] = min(record_lengths)
        except ArithmeticError:
            print("Division by zero error")
            data['statistics']['Average Record Length'] = 0
            data['statistics']['Median Record Length'] = 0
            data['statistics']['Max Record Length'] = 0
            data['statistics']['Min Record Length'] = 0

    # --- Compute TLS Content Type Frequency ---
    tls_ct_counts = {}
    for ct in data['tls_content_type']:
        tls_ct_counts[ct] = tls_ct_counts.get(ct, 0) + 1
    data['statistics']['TLS Content Type Counts'] = tls_ct_counts

    # --- Compute TLS Version Frequency ---
    tls_ver_counts = {}
    for ver in data['tls_version']:
        tls_ver_counts[ver] = tls_ver_counts.get(ver, 0) + 1
    data['statistics']['TLS Version Counts'] = tls_ver_counts

    # --- Compute Packet Size Statistics ---
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

    # --- Compute TTL Statistics ---
    ttls = data['ttl values']
    if ttls:
        data['statistics']['Average TTL'] = statistics.mean(ttls)
        data['statistics']['Median TTL'] = statistics.median(ttls)
        data['statistics']['Min TTL'] = min(ttls)
        data['statistics']['Max TTL'] = max(ttls)
        data['statistics']['STD TTL'] = statistics.pstdev(ttls) if len(ttls) > 1 else 0.0
    else:
        data['statistics']['Average TTL'] = 0
        data['statistics']['Median TTL'] = 0
        data['statistics']['Min TTL'] = 0
        data['statistics']['Max TTL'] = 0
        data['statistics']['STD TTL'] = 0

    # --- Compute IP ID Statistics (for IPv4) ---
    if data['ip_ids']:
        ip_ids = data['ip_ids']
        data['statistics']['Average IP ID'] = statistics.mean(ip_ids)
        data['statistics']['Median IP ID'] = statistics.median(ip_ids)
        data['statistics']['Max IP ID'] = max(ip_ids)
        data['statistics']['Min IP ID'] = min(ip_ids)
        data['statistics']['STD IP ID'] = statistics.pstdev(ip_ids) if len(ip_ids) > 1 else 0.0
    else:
        data['statistics']['Average IP ID'] = 0
        data['statistics']['Median IP ID'] = 0
        data['statistics']['Max IP ID'] = 0
        data['statistics']['Min IP ID'] = 0
        data['statistics']['STD IP ID'] = 0

    # --- Compute TCP Window Size Statistics ---
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

    # --- Compute Time Difference Statistics ---
    tdiff = data['time_diff']
    if tdiff:
        data['statistics']['Average Time Difference Between Packets'] = statistics.mean(tdiff)
        data['statistics']['Median Time Difference Between Packets'] = statistics.median(tdiff)
        data['statistics']['STD Time Difference Between Packets'] = statistics.pstdev(tdiff) if len(tdiff) > 1 else 0.0
    else:
        data['statistics']['Average Time Difference Between Packets'] = 0
        data['statistics']['Median Time Difference Between Packets'] = 0
        data['statistics']['STD Time Difference Between Packets'] = 0

    # --- Manually Count TCP Flags ---
    tcp_flag_counts = {}
    for flag in data['tcp_flags']:
        tcp_flag_counts[flag] = tcp_flag_counts.get(flag, 0) + 1
    data['statistics']['TCP Flags Counts'] = tcp_flag_counts

    return data


def plot_results(pcapng_results, file_names, output_dir='output'):
    os.makedirs(output_dir, exist_ok=True)
    plot_fig_size = (12, 6)
    sub_plot_fig_size = (24, 12)

    # Plot Packet Size Histogram
    plt.figure(figsize=plot_fig_size)
    for i, file in enumerate(file_names):
        plt.hist(pcapng_results[i]['packet_sizes'], bins=30, alpha=0.5, label=file)
    plt.title('Packet Size')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.legend()
    plt.savefig(os.path.join(output_dir, 'Packet Size.png'))
    plt.close()

    # Plot Time Difference Boxplot
    plt.figure(figsize=plot_fig_size)
    time_diff_data = [pcapng_results[i]['time_diff'] for i in range(len(file_names))]
    plt.boxplot(time_diff_data, labels=file_names)
    plt.xticks(rotation=10)
    plt.title('Time Difference Between Packets')
    plt.ylabel('Time (sec)')
    plt.savefig(os.path.join(output_dir, 'Time Difference Between Packets.png'))
    plt.close()

    # Plot Protocols Count
    plt.figure(figsize=plot_fig_size)
    protocol_names = set()
    for result in pcapng_results:
        protocol_names.update(result['protocol_counts'].keys())
    protocol_names = list(protocol_names)

    bar_width = 0.15
    x_line = range(len(protocol_names))
    for i, file in enumerate(file_names):
        counts = []
        for protocol in protocol_names:
            counts.append(pcapng_results[i]['protocol_counts'].get(protocol, 0))
        positions = [pos + (i * bar_width) for pos in x_line]
        bars = plt.bar(positions, counts, bar_width, label=file)
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, height, f'{height:.0f}', ha='center', va='bottom', fontsize=10)
    label_positions = [pos + (bar_width * (len(file_names) / 2)) for pos in x_line]
    plt.xticks(label_positions, protocol_names)
    plt.title('Protocols Count')
    plt.ylabel('Packet Count')
    plt.legend()
    plt.savefig(os.path.join(output_dir, 'Protocols Count.png'))
    plt.close()

    # Plot Flow Count
    plt.figure(figsize=plot_fig_size)
    flow_counts = [len(res['flows']) for res in pcapng_results]
    bars = plt.bar(file_names, flow_counts, alpha=0.6, label='Number of Flows')
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height, f'{height:.0f}', ha='center', va='bottom', fontsize=10)
    plt.xticks(rotation=10)
    plt.title('Flow Count')
    plt.ylabel('Count')
    plt.legend()
    plt.savefig(os.path.join(output_dir, 'Flow Count.png'))
    plt.close()

    # Define groups of statistics to plot as bar charts.
    statistics_keys = {
        'TLS Record Length Statistics': [
            'Average Record Length',
            'Median Record Length',
            'Max Record Length',
            'Min Record Length'
        ],
        'Packet Size Statistics': [
            'Average Packet Size',
            'Median Packet Size',
            'Max Packet Size',
            'STD Packet Size'
        ],
        'Time Difference Between Packets Statistics': [
            'Average Time Difference Between Packets',
            'Median Time Difference Between Packets',
            'STD Time Difference Between Packets'
        ],
        'TTL Statistics': [
            'Average TTL',
            'Median TTL',
            'Min TTL',
            'Max TTL',
            'STD TTL'
        ],
        'TCP Window Size Statistics': [
            'Average Window Size',
            'Median Window Size',
            'Max Window Size',
            'STD Window Size'
        ]
    }

    for plot_group, keys in statistics_keys.items():
        plt.figure(figsize=sub_plot_fig_size)
        for idx, key in enumerate(keys):
            plt.subplot(2, 3, idx + 1)
            current_values = [res['statistics'].get(key, 0) for res in pcapng_results]
            plt.bar(file_names, current_values, color='green', alpha=0.7)
            for j, value in enumerate(current_values):
                plt.text(j, value, f'{value:.2f}', ha='center', va='bottom', fontsize=10)
            plt.xticks(rotation=10)
            plt.title(key)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{plot_group}.png'))
        plt.close()

    # Optionally, plot frequency distributions for TLS Content Type, TLS Version, and TCP Flags.
    # TLS Content Type Frequency
    plt.figure(figsize=plot_fig_size)
    for i, file in enumerate(file_names):
        # For each file, extract the TLS Content Type frequency dictionary.
        freq_dict = pcapng_results[i]['statistics'].get('TLS Content Type Counts', {})
        keys_ct = list(freq_dict.keys())
        values_ct = [freq_dict[k] for k in keys_ct]
        plt.bar([f"{file}-{k}" for k in keys_ct], values_ct, alpha=0.7, label=file)
    plt.xticks(rotation=45)
    plt.title('TLS Content Type Frequency')
    plt.ylabel('Count')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'TLS Content Type Frequency.png'))
    plt.close()

    # TLS Version Frequency
    plt.figure(figsize=plot_fig_size)
    for i, file in enumerate(file_names):
        freq_dict = pcapng_results[i]['statistics'].get('TLS Version Counts', {})
        keys_ver = list(freq_dict.keys())
        values_ver = [freq_dict[k] for k in keys_ver]
        plt.bar([f"{file}-{k}" for k in keys_ver], values_ver, alpha=0.7, label=file)
    plt.xticks(rotation=45)
    plt.title('TLS Version Frequency')
    plt.ylabel('Count')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'TLS Version Frequency.png'))
    plt.close()

    # TCP Flags Frequency (manually counted earlier)
    plt.figure(figsize=plot_fig_size)
    for i, file in enumerate(file_names):
        freq_dict = pcapng_results[i]['statistics'].get('TCP Flags Counts', {})
        keys_flags = list(freq_dict.keys())
        values_flags = [freq_dict[k] for k in keys_flags]
        plt.bar([f"{file}-{k}" for k in keys_flags], values_flags, alpha=0.7, label=file)
    plt.xticks(rotation=45)
    plt.title('TCP Flags Frequency')
    plt.ylabel('Count')
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'TCP Flags Frequency.png'))
    plt.close()


def main():
    try:
        with open('pcapng_files.txt') as f:
            pcapng_files = f.read().splitlines()
    except FileNotFoundError as e:
        print(f"Error: pcapng_files.txt not found. {e}")
        return

    pcapng_results = []
    for pcapng_file in pcapng_files:
        try:
            tls_key_file = get_tls_keylog_file(pcapng_file)
            results = analyze_pcapng(pcapng_file, tls_key_file)
            pcapng_results.append(results)
        except Exception as e:
            print(f"Error processing {pcapng_file}: {e}")
            continue

    pcapng_names = [os.path.basename(p) for p in pcapng_files]
    try:
        plot_results(pcapng_results, pcapng_names)
    except Exception as e:
        print(f"Error plotting results: {e}")
    except KeyboardInterrupt:
        print("\nBye!")

    print("Finished Analyzing, Statistic Photos are in the output directory (:")

if __name__ == '__main__':
    main()
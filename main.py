import pyshark
import matplotlib.pyplot as plt
import statistics
import os


def analyze_pcapng(pcapng_file):
    print(f'analysing {pcapng_file}')
    capture = pyshark.FileCapture(pcapng_file, keep_packets=False, use_json=True)

    data = {
        'packet_sizes': [],
        'time_diff': [],
        'flows': {},
        'protocol_counts': {},
        'stats': {}
    }

    arrival_times = []

    for packet in capture:
        try:
            # pack size
            pkt_size = int(packet.length)
            data['packet_sizes'].append(pkt_size)

            # pack time
            sniff_time = packet.sniff_time
            arrival_times.append(sniff_time)

            # ip layer
            if hasattr(packet, 'ip'):
                ip_version = 'IPv4'
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                ip_version = 'IPv6'
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
            else:
                continue  # skip if no ipv4 or ipv6

            # transport layer
            if hasattr(packet, 'quic'):
                transport = 'QUIC'
            elif hasattr(packet, 'tcp'):
                transport = 'TCP'
            elif hasattr(packet, 'udp'):
                transport = 'UDP'
            else:
                transport = packet.highest_layer

            # define new key if needed
            if transport not in data['protocol_counts']:
                data['protocol_counts'][transport] = 0

            # update the transport protocol in the data
            data['protocol_counts'][transport] += 1

            # handle tls protocol
            if hasattr(packet, 'tls'):
                if 'TLS' not in data['protocol_counts']:
                    data['protocol_counts']['TLS'] = 0
                data['protocol_counts']['TLS'] += 1

            # handle dns protocol
            if hasattr(packet, 'dns'):
                if 'DNS' not in data['protocol_counts']:
                    data['protocol_counts']['DNS'] = 0
                data['protocol_counts']['DNS'] += 1

            # flow - (ip, src ip, dst ip, src port, dst port, transport protocol)
            src_port = getattr(packet, transport.lower())
            dst_port = getattr(packet, transport.lower())
            flow_key = (ip_version, src_ip, dst_ip, src_port, dst_port, transport)

            # define new key if needed
            if flow_key not in data['flows']:
                data['flows'][flow_key] = {'packet_count': 0, 'byte_count': 0}

            # update the flow in the data
            data['flows'][flow_key]['packet_count'] += 1
            data['flows'][flow_key]['byte_count'] += pkt_size

        except AttributeError:
            continue

    capture.close()

    # calculate diff time between the packets
    if len(arrival_times) > 1:
        arrival_times.sort()
        data['time_diff'] = []
        for i in range(0, len(arrival_times) - 1):
            time_diff = (arrival_times[i + 1] - arrival_times[i]).total_seconds()
            data['time_diff'].append(time_diff)

    # calculate statistics for packet sizes
    pkt_sizes = data['packet_sizes']
    if pkt_sizes:
        data['stats']['avg_pkt_size'] = statistics.mean(pkt_sizes)
        data['stats']['median_pkt_size'] = statistics.median(pkt_sizes)
        data['stats']['max_pkt_size'] = max(pkt_sizes)
        data['stats']['min_pkt_size'] = min(pkt_sizes)
        data['stats']['std_pkt_size'] = statistics.pstdev(pkt_sizes) if len(pkt_sizes) > 1 else 0.0
    else:
        data['stats']['avg_pkt_size'] = 0
        data['stats']['median_pkt_size'] = 0
        data['stats']['max_pkt_size'] = 0
        data['stats']['min_pkt_size'] = 0
        data['stats']['std_pkt_size'] = 0

    # calculate statistics for time diff
    time_diff = [td for td in data['time_diff']]
    if time_diff:
        data['stats']['avg_time_diff'] = statistics.mean(time_diff)
        data['stats']['median_time_diff'] = statistics.median(time_diff)
        data['stats']['std_time_diff'] = statistics.pstdev(time_diff) if len(time_diff) > 1 else 0.0
    else:
        data['stats']['avg_time_diff'] = 0
        data['stats']['median_time_diff'] = 0
        data['stats']['std_time_diff'] = 0

    return data


def plot_results(pcapng_results, file_names, output_dir='output'):

    os.makedirs(output_dir, exist_ok=True)

    fig_size = (12, 6)

    # 1. packet Size
    plt.figure(figsize=fig_size)
    for i, file in enumerate(file_names):  # run over the data with the indexes
        plt.hist(pcapng_results[i]['packet_sizes'], bins=30, alpha=0.5, label=file)
    plt.title('Packet Size')
    plt.xlabel('Packet Size (bytes)')
    plt.ylabel('Frequency')
    plt.legend()
    plt.savefig(f'{output_dir}/Packet Size.png')
    plt.close()

    # 2. time difference between packets
    plt.figure(figsize=fig_size)
    time_diff_data = [pcapng_results[i]['time_diff'] for i in range(len(file_names))]
    plt.boxplot(time_diff_data, tick_labels=file_names)

    plt.xticks(rotation=10)
    plt.title('Time Difference Between Packets')
    plt.ylabel('Time (sec)')
    plt.savefig(f'{output_dir}/Time Difference Between Packets.png')
    plt.close()

    # 3. protocols count
    plt.figure(figsize=fig_size)

    # collect all protocols
    protocol_names = set()
    for result in pcapng_results:
        protocol_names.update(result['protocol_counts'].keys())

    # define bars layout
    bar_width = 0.15
    x_line = range(len(protocol_names))

    for i, file in enumerate(file_names):  # run over the data with the indexes

        counts = []
        for protocol in protocol_names:
            count = pcapng_results[i]['protocol_counts'][protocol] \
                if protocol in pcapng_results[i]['protocol_counts'].keys() else 0
            counts.append(count)

        #  define bars positions
        positions = [position + (i * bar_width) for position in x_line]
        bars = plt.bar(positions, counts, bar_width, label=file)

        # add labels on the bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, height, f'{height:.0f}',
                     ha='center', va='bottom', fontsize=10)

    label_positions = []
    for position in x_line:
        label_positions.append(position + (bar_width * (len(file_names) / 2)))
    plt.xticks(label_positions, list(protocol_names))
    plt.title('Protocols Count')
    plt.ylabel('Packet Count')
    plt.legend()
    plt.savefig(f'{output_dir}/Protocols Count.png')
    plt.close()

    # 4. flow count ---
    plt.figure(figsize=fig_size)

    flow_counts = []
    for i in range(len(file_names)):
        flow_counts.append(len(pcapng_results[i]['flows']))

    bars = plt.bar(file_names, flow_counts, alpha=0.6, label='Number of Flows')

    # add labels on the bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, height, f'{height:.0f}',
                 ha='center', va='bottom', fontsize=10)

    plt.xticks(rotation=10)
    plt.title('Flow Count')
    plt.ylabel('Count')
    plt.legend()
    plt.savefig(f'{output_dir}/Flow Count.png')
    plt.close()

    # 5. average packet size
    plt.figure(figsize=fig_size)
    avg_pkt_sizes = [pcapng_results[i]['stats']['avg_pkt_size'] for i in range(len(file_names))]

    plt.xticks(rotation=10)
    plt.bar(file_names, avg_pkt_sizes, color='orange', alpha=0.7)

    # add labels on the bars
    for i, value in enumerate(avg_pkt_sizes):  # run over the data with the indexes
        plt.text(i, value, f'{value:.2f}', ha='center', va='bottom', fontsize=10)

    plt.xticks(rotation=10)
    plt.title('Average Packet Size')
    plt.ylabel('Bytes')
    plt.savefig(f'{output_dir}/Average Packet Size.png')
    plt.close()

    # 6. average time diff
    plt.figure(figsize=fig_size)
    avg_time_diff = [pcapng_results[i]['stats']['avg_time_diff'] for i in range(len(file_names))]
    plt.bar(file_names, avg_time_diff, color='green', alpha=0.7)

    # add labels on the bars
    for i, value in enumerate(avg_time_diff):
        plt.text(i, value, f'{value:.6f}', ha='center', va='bottom', fontsize=10)

    plt.xticks(rotation=10)
    plt.title('Average Time Difference Between Packets')
    plt.ylabel('Seconds')
    plt.savefig(f'{output_dir}/Average Time Difference Between Packets.png')
    plt.close()


def main():

    with open('pcapng_files.txt') as file:
        pcapng_files = file.read().splitlines()

    pcapng_results = []
    for pcapng_file in pcapng_files:
        pcapng_results.append(analyze_pcapng(pcapng_file))

    pcapng_names = [pcapng.split('/')[-1] for pcapng in pcapng_files]
    plot_results(pcapng_results, pcapng_names)


if __name__ == '__main__':
    main()

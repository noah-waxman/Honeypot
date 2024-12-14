import os
import re
from datetime import datetime
from collections import Counter, defaultdict
import json
import ipaddress
import matplotlib.pyplot as plt
from geolite2 import geolite2

class IPStats:
    def __init__(self):
        self.failed_command_attempts = Counter()
        self.total_commands = 0
        self.failed_commands = 0
        self.commands = Counter()
        self.successful_auths = 0
        self.failed_auths = 0
        self.usernames = Counter()
        self.passwords = Counter()
        self.sessions = set()
        self.first_seen = None
        self.last_seen = None
        self.country = None

def create_visualizations(report):
    # Attack frequency over time
    plt.figure(figsize=(12, 6))
    hours = list(report['global_stats']['temporal_distribution'].keys())
    counts = list(report['global_stats']['temporal_distribution'].values())
    plt.bar(hours, counts)
    plt.title('Attack Distribution by Hour')
    plt.xlabel('Hour of Day')
    plt.ylabel('Number of Attacks')
    plt.savefig('attack_distribution.png')
    plt.close()
    
    # Geographical heatmap using folium
    import folium
    world_map = folium.Map()
    
    # Get geolocation data
    reader = geolite2.reader()
    
    for ip_data in report['ip_analysis']['active_ips']:
        try:
            geo_data = reader.get(ip_data['ip'])
            if geo_data and 'location' in geo_data:
                location = [
                    geo_data['location']['latitude'],
                    geo_data['location']['longitude']
                ]
                folium.Circle(
                    location=location,
                    radius=ip_data['total_commands'] * 100,
                    color='red',
                    fill=True
                ).add_to(world_map)
        except:
            continue
            
    geolite2.close()
    world_map.save('attack_origins.html')

def create_enhanced_visualizations(report):
    # 1. Top 10 Usernames and Passwords
    plt.figure(figsize=(15, 6))
    
    plt.subplot(1, 2, 1)
    usernames = dict(sorted(report['global_stats']['usernames'].items(), 
                          key=lambda x: x[1], reverse=True)[:10])
    plt.bar(usernames.keys(), usernames.values())
    plt.xticks(rotation=45, ha='right')
    plt.title('Top 10 Attempted Usernames')
    plt.ylabel('Frequency')
    
    plt.subplot(1, 2, 2)
    passwords = dict(sorted(report['global_stats']['passwords'].items(), 
                          key=lambda x: x[1], reverse=True)[:10])
    plt.bar(passwords.keys(), passwords.values())
    plt.xticks(rotation=45, ha='right')
    plt.title('Top 10 Attempted Passwords')
    plt.ylabel('Frequency')
    
    plt.tight_layout()
    plt.savefig('credentials_analysis.png')
    plt.close()

    # 2. Improved Command Categories Distribution
        # 2. Improved Command Categories Distribution
    command_categories = {
        'System Reconnaissance': [
            'uname', 'whoami', 'uptime', 'hostname', '/proc/cpuinfo', 'lscpu', 
            'free', '/proc/uptime', '/etc/issue', 'cat /proc'
        ],
        'Malware Download & Execution': [
            'wget http', 'curl http', 'bins.sh', 'lol.sh', '/dev/tcp/', 
            'chmod 777', './x86', 'mexalz', 'nohup'
        ],
        'SSH Activities': [
            '.ssh', 'authorized_keys', 'ssh-rsa', 'ssh.scan', 'chattr'
        ],
        'Basic File Operations': [
            'cd', 'ls', 'cat', 'rm -rf', 'chmod', 'mkdir'
        ],
        'System Manipulation': [
            'ulimit', 'sysctl.conf', 'history -c', '.bash_history',
            'echo -e', 'echo -n'
        ],
        'Hardware Inspection': [
            'nvidia-smi', 'lspci', 'grep VGA', 'grep name'
        ],
        'Process Monitoring': [
            'ps', 'grep miner', 'uptime'
        ],
        'Other': []
    }

    category_counts = {cat: 0 for cat in command_categories.keys()}

    def categorize_command(cmd):
        cmd_lower = cmd.lower()
        for category, patterns in command_categories.items():
            if any(pattern.lower() in cmd_lower for pattern in patterns):
                return category
        return 'Other'

    for cmd, count in report['global_stats']['commands'].items():
        category = categorize_command(cmd)
        category_counts[category] += count

    # Filter out categories with very small percentages (less than 1%)
    total_commands = sum(category_counts.values())
    significant_categories = {
        k: v for k, v in category_counts.items() 
        if (v / total_commands) * 100 >= 1.0
    }

    plt.figure(figsize=(12, 8))
    plt.pie(significant_categories.values(),
            labels=significant_categories.keys(),
            autopct='%1.1f%%',
            explode=[0.05] * len(significant_categories))
    plt.title('Command Categories Distribution')
    plt.savefig('command_categories.png', bbox_inches='tight')
    plt.close()


    # 3. Improved Attack Success Rate by Country
    country_stats = defaultdict(lambda: {'success': 0, 'failure': 0})
    
    for ip_data in report['ip_analysis']['active_ips']:
        country = ip_data['country'] if ip_data['country'] else 'Unknown'
        country_stats[country]['success'] += ip_data['successful_auths']
        country_stats[country]['failure'] += ip_data['failed_auths']

    # Filter and sort countries by total activity
    active_countries = {k: v for k, v in country_stats.items() 
                       if v['success'] + v['failure'] > 0}
    
    # Get top 10 countries instead of 15
    top_countries = dict(sorted(active_countries.items(), 
                              key=lambda x: x[1]['success'] + x[1]['failure'], 
                              reverse=True)[:10])

    countries = list(top_countries.keys())
    success_rates = [stats['success']/(stats['success'] + stats['failure']) * 100 
                    for stats in top_countries.values()]
    
    plt.figure(figsize=(12, 6))
    bars = plt.bar(range(len(countries)), success_rates)
    plt.xticks(range(len(countries)), countries, rotation=45, ha='right')
    plt.title('Attack Success Rate by Top 10 Countries')
    plt.ylabel('Success Rate (%)')
    
    # Add value labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f}%',
                ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig('country_success_rates.png')
    plt.close()

    # 4. Timeline of Attack Intensity
    plt.figure(figsize=(15, 6))
    hours = list(report['global_stats']['temporal_distribution'].keys())
    counts = list(report['global_stats']['temporal_distribution'].values())
    
    plt.plot(hours, counts, marker='o')
    plt.fill_between(hours, counts, alpha=0.3)
    plt.title('Attack Intensity Timeline')
    plt.xlabel('Hour of Day')
    plt.ylabel('Number of Events')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.savefig('attack_timeline.png')
    plt.close()

    # 5. Command Success vs Failure Rate
    total_commands = sum(report['global_stats']['commands'].values())
    failed_commands = sum(ip_data['failed_commands'] for ip_data in report['ip_analysis']['active_ips'])
    successful_commands = total_commands - failed_commands
    
    plt.figure(figsize=(8, 8))
    plt.pie([successful_commands, failed_commands], 
            labels=['Successful', 'Failed'],
            colors=['green', 'red'],
            autopct='%1.1f%%')
    plt.title('Command Success vs Failure Rate')
    plt.savefig('command_success_rate.png')
    plt.close()


def analyze_sessions(stats):
    session_metrics = {
        'duration': [],
        'command_sequences': [],
        'interaction_patterns': []
    }
    
    # Modified to handle the current data structure
    for ip, sessions in stats['ip_sessions'].items():
        session_count = len(sessions)
        session_metrics['interaction_patterns'].append({
            'ip': ip,
            'session_count': session_count
        })
    
    return session_metrics


def analyze_malware_attempts(stats):
    malware_indicators = {
        'download_attempts': [],
        'suspicious_commands': [],
        'potential_payloads': []
    }
    
    suspicious_patterns = [
        'wget', 'curl', '.sh', '.bin', 
        'tftp', 'base64', 'chmod'
    ]
    
    # Analyze commands directly from source_ips
    for ip, ip_data in stats['source_ips'].items():
        for cmd, count in ip_data.commands.items():
            for pattern in suspicious_patterns:
                if pattern in cmd.lower():
                    malware_indicators['suspicious_commands'].append({
                        'ip': ip,
                        'command': cmd,
                        'count': count,
                        'timestamp': ip_data.first_seen.isoformat() if ip_data.first_seen else None
                    })
    
    return malware_indicators


def classify_attacks(stats):
    attack_types = {
        'bruteforce': 0,
        'automated_scan': 0,
        'targeted_attack': 0,
        'reconnaissance': 0
    }
    
    # Use source_ips directly from stats
    for ip, ip_data in stats['source_ips'].items():
        # Classify based on behavior patterns
        if ip_data.failed_auths > 100:
            attack_types['bruteforce'] += 1
        if ip_data.total_commands < 5 and len(ip_data.sessions) > 10:
            attack_types['automated_scan'] += 1
        
    return attack_types



def analyze_logs(log_dir):
    stats = {
        "auth_attempts": {"total": 0, "success": 0, "failure": 0},
        "auth_users": Counter(),
        "auth_passwords": Counter(),
        "source_ips": defaultdict(IPStats),
        "commands": Counter(),
        "sessions": {"total": 0, "durations": []},
        "ip_sessions": defaultdict(dict),
        "temporal_data": defaultdict(int),
        "auth_patterns": defaultdict(int)
    }

    auth_attempt_re = re.compile(r"login attempt \[b'(?P<username>.*?)'/b'(?P<password>.*?)'\] (succeeded|failed)")
    command_re = re.compile(r"CMD: (?P<command>.+)")
    failed_command_re = re.compile(r"Command not found: (?P<command>.+)")
    session_ip_re = re.compile(r"New connection: (?P<ip>\d+\.\d+\.\d+\.\d+).+\[session: (?P<session_id>\w+)]")
    timestamp_re = re.compile(r"^(?P<timestamp>[\d\-T:.]+Z)")

    current_session = None
    current_ip = None
    
    geo_reader = geolite2.reader()

    for log_file in os.listdir(log_dir):
        if log_file.startswith("cowrie.log."):
            with open(os.path.join(log_dir, log_file), 'r') as f:
                for line in f:
                    failed_match = failed_command_re.search(line)
                    if failed_match and current_ip:
                        failed_command = failed_match.group("command")
                        stats["source_ips"][current_ip].failed_commands += 1
                        stats["source_ips"][current_ip].failed_command_attempts[failed_command] += 1  # Track failed command


                    timestamp_match = timestamp_re.search(line)
                    if timestamp_match:
                        current_time = datetime.strptime(timestamp_match.group("timestamp"), "%Y-%m-%dT%H:%M:%S.%fZ")
                        stats["temporal_data"][current_time.hour] += 1

                    session_ip_match = session_ip_re.search(line)
                    if session_ip_match:
                        session_id = session_ip_match.group("session_id")
                        ip = session_ip_match.group("ip")
                        stats["ip_sessions"][ip][session_id] = True
                        current_session = session_id
                        current_ip = ip
                        stats["source_ips"][ip].sessions.add(session_id)
                        
                        if stats["source_ips"][ip].first_seen is None:
                            stats["source_ips"][ip].first_seen = current_time
                            try:
                                geo_data = geo_reader.get(ip)
                                if geo_data:
                                    stats["source_ips"][ip].country = geo_data.get('country', {}).get('iso_code', 'Unknown')
                            except:
                                stats["source_ips"][ip].country = 'Unknown'
                        stats["source_ips"][ip].last_seen = current_time

                    auth_match = auth_attempt_re.search(line)
                    if auth_match and current_ip:
                        username = auth_match.group("username")
                        password = auth_match.group("password")
                        is_success = "succeeded" in line
                        
                        stats["auth_attempts"]["total"] += 1
                        stats["auth_attempts"]["success" if is_success else "failure"] += 1
                        stats["auth_users"][username] += 1
                        stats["auth_passwords"][password] += 1
                        stats["auth_patterns"][f"{username}:{password}"] += 1
                        
                        ip_stats = stats["source_ips"][current_ip]
                        if is_success:
                            ip_stats.successful_auths += 1
                        else:
                            ip_stats.failed_auths += 1
                        ip_stats.usernames[username] += 1
                        ip_stats.passwords[password] += 1

                    command_match = command_re.search(line)
                    if command_match and current_ip:
                        command = command_match.group("command")
                        stats["commands"][command] += 1
                        stats["source_ips"][current_ip].commands[command] += 1
                        stats["source_ips"][current_ip].total_commands += 1

                    failed_match = failed_command_re.search(line)
                    if failed_match and current_ip:
                        stats["source_ips"][current_ip].failed_commands += 1

    geolite2.close()
    return stats

def generate_enhanced_report(stats):
    report = {
        "summary": {
            "total_auth_attempts": stats["auth_attempts"]["total"],
            "successful_auths": stats["auth_attempts"]["success"],
            "failed_auths": stats["auth_attempts"]["failure"],
            "unique_ips": len(stats["source_ips"]),
            "total_commands": sum(stats["commands"].values())
        },
        "ip_analysis": {},
        "global_stats": {
            "commands": dict(stats["commands"]),
            "usernames": dict(stats["auth_users"]),
            "passwords": dict(stats["auth_passwords"]),
            "auth_patterns": dict(sorted(stats["auth_patterns"].items(), key=lambda x: x[1], reverse=True)),
            "temporal_distribution": dict(stats["temporal_data"])
        }
    }

    ip_stats = []
    for ip, ip_data in stats["source_ips"].items():
        ip_stats.append({
            "ip": ip,
            "country": ip_data.country,
            "total_commands": ip_data.total_commands,
            "failed_commands": ip_data.failed_commands,
            "successful_auths": ip_data.successful_auths,
            "failed_auths": ip_data.failed_auths,
            "unique_sessions": len(ip_data.sessions),
            "commands": dict(ip_data.commands),
            "usernames": dict(ip_data.usernames),
            "passwords": dict(ip_data.passwords),
            "first_seen": ip_data.first_seen.isoformat() if ip_data.first_seen else None,
            "last_seen": ip_data.last_seen.isoformat() if ip_data.last_seen else None
        })

    ip_stats.sort(key=lambda x: x["total_commands"] + x["successful_auths"] + x["failed_auths"], reverse=True)
    report["ip_analysis"]["active_ips"] = ip_stats

    return report

def print_top_countries(report, top_n=10):
    # Create a dictionary to store country counts
    country_counts = defaultdict(int)
    
    # Count occurrences of each country
    for ip_data in report['ip_analysis']['active_ips']:
        country = ip_data['country'] if ip_data['country'] else 'Unknown'
        country_counts[country] += ip_data['total_commands'] + ip_data['successful_auths'] + ip_data['failed_auths']
    
    # Sort and get top N countries
    top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    print("\nTop {} Attacking Countries:".format(top_n))
    for country, count in top_countries:
        print(f"{country}: {count} activities")


def print_top_commands(report, top_n=10):
    # Get commands from the report and sort them by frequency
    commands = report['global_stats']['commands']
    top_commands = sorted(commands.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    print(f"\nTop {top_n} Most Used Commands:")
    for command, count in top_commands:
        print(f"{command}: {count} times")

def analyze_limited_command_behavior(stats):
    behavior_analysis = {}

    for ip, ip_data in stats["source_ips"].items():
        if ip_data.failed_commands > 0:
            behavior_analysis[ip] = {
                "failed_commands": ip_data.failed_commands,
                "failed_command_attempts": dict(ip_data.failed_command_attempts)
            }

    return behavior_analysis

def print_top_failed_commands(stats, top_n=10):
    # Aggregate all failed command attempts from all IPs
    all_failed_commands = Counter()
    for ip_data in stats["source_ips"].values():
        all_failed_commands.update(ip_data.failed_command_attempts)

    # Sort and get the top N failed commands
    top_failed_commands = all_failed_commands.most_common(top_n)

    print(f"\nTop {top_n} Failed Commands:")
    for command, count in top_failed_commands:
        print(f"{command}: {count} times")

def print_session_statistics(stats):
    # Calculate total sessions and total duration
    total_sessions = len(stats['ip_sessions'])
    total_durations = [duration for ip_sessions in stats['ip_sessions'].values() for duration in ip_sessions.values()]
    total_duration = sum(total_durations)
    
    # Calculate average session duration
    average_duration = total_duration / total_sessions if total_sessions > 0 else 0

    # Calculate the average number of sessions per IP
    average_sessions_per_ip = total_sessions / len(stats['source_ips']) if len(stats['source_ips']) > 0 else 0

    print("\nSession Statistics:")
    print(f"Total Sessions: {total_sessions}")
    print(f"Average Session Duration: {average_duration:.2f} seconds")
    print(f"Average Sessions per IP: {average_sessions_per_ip:.2f}")



def main():
    log_directory = '.'
    stats = analyze_logs(log_directory)
    report = generate_enhanced_report(stats)
    
    # Add new analyses
    report['session_analysis'] = analyze_sessions(stats)
    report['malware_analysis'] = analyze_malware_attempts(stats)
    report['attack_classification'] = classify_attacks(stats)
    report['limited_command_behavior'] = analyze_limited_command_behavior(stats)  # New analysis
    
    # Generate visualizations
    create_visualizations(report)
    create_enhanced_visualizations(report)  # New visualizations

    print_top_countries(report)
    print_top_commands(report)

    # Print analysis of limited command behavior
    print_top_failed_commands(stats)
    print_session_statistics(stats)

    
    # # Print enhanced summary to console
    # print("\n=== Cowrie Honeypot Analysis Report ===")
    # print("\nGlobal Statistics:")
    # print(f"Total Auth Attempts: {report['summary']['total_auth_attempts']}")
    # print(f"Successful Auths: {report['summary']['successful_auths']}")
    # print(f"Failed Auths: {report['summary']['failed_auths']}")
    # print(f"Unique IPs: {report['summary']['unique_ips']}")
    # print(f"Total Commands: {report['summary']['total_commands']}")
    
    # print("\nAttacking IPs (showing all):")
    # for ip_data in report["ip_analysis"]["active_ips"]:
    #     print(f"\nIP: {ip_data['ip']} (Country: {ip_data['country']})")
    #     print(f"  Total Commands: {ip_data['total_commands']}")
    #     print(f"  Failed Commands: {ip_data['failed_commands']}")
    #     print(f"  Successful Auths: {ip_data['successful_auths']}")
    #     print(f"  Failed Auths: {ip_data['failed_auths']}")
    #     print(f"  Unique Sessions: {ip_data['unique_sessions']}")
    #     print(f"  First Seen: {ip_data['first_seen']}")
    #     print(f"  Last Seen: {ip_data['last_seen']}")

if __name__ == "__main__":
    main()

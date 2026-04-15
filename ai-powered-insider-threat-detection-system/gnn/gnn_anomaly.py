"""
Graph Feature Engineering

Computes graph-based features including:
- Degree centrality
- Betweenness centrality
- PageRank scores
- Community detection metrics

Builds a bipartite graph of users <-> files/devices
"""

import pandas as pd
import networkx as nx
import os

DATA_DIR = 'data'

def load_logs():
    """Load file access and USB logs."""
    file_access_path = os.path.join(DATA_DIR, 'file_access.csv')
    usb_usage_path = os.path.join(DATA_DIR, 'usb_usage.csv')

    file_access = pd.read_csv(file_access_path, parse_dates=['access_time']) if os.path.exists(file_access_path) else None
    usb_usage = pd.read_csv(usb_usage_path, parse_dates=['plug_time', 'unplug_time']) if os.path.exists(usb_usage_path) else None

    return file_access, usb_usage

def build_graph(file_access, usb_usage):
    """Build bipartite graph of users and resources."""
    G = nx.Graph()

    if file_access is not None:
        for _, row in file_access.iterrows():
            G.add_edge(row['user'], row['file'], type='file_access', weight=1)

    if usb_usage is not None:
        for _, row in usb_usage.iterrows():
            G.add_edge(row['user'], row['device_id'], type='usb_access', weight=1)

    return G

def compute_graph_features():
    """Compute graph-based features for each user."""
    print("Computing graph features...")

    file_access, usb_usage = load_logs()

    if file_access is None:
        print("No file access data found!")
        return

    # Build graph
    G = build_graph(file_access, usb_usage)
    print(f"Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Get user nodes
    user_nodes = [n for n in G.nodes() if str(n).startswith('user')]
    print(f"Analyzing {len(user_nodes)} users...")

    # Compute centrality measures
    print("  Computing degree centrality...")
    degree = nx.degree_centrality(G)

    print("  Computing betweenness centrality...")
    betweenness = nx.betweenness_centrality(G)

    print("  Computing PageRank...")
    pagerank = nx.pagerank(G, max_iter=100)

    print("  Computing clustering coefficient...")
    clustering = nx.clustering(G)

    # Build feature dataframe
    features = []
    for user in user_nodes:
        # Count direct connections
        user_degree = G.degree[user] if user in G else 0

        # Count unique files and devices
        if file_access is not None:
            user_files = file_access[file_access['user'] == user]['file'].nunique()
        else:
            user_files = 0

        if usb_usage is not None:
            user_devices = usb_usage[usb_usage['user'] == user]['device_id'].nunique()
        else:
            user_devices = 0

        features.append({
            'user': user,
            'degree_centrality': degree.get(user, 0),
            'betweenness_centrality': betweenness.get(user, 0),
            'pagerank': pagerank.get(user, 0),
            'clustering_coefficient': clustering.get(user, 0),
            'direct_connections': user_degree,
            'unique_files_accessed': user_files,
            'unique_devices_used': user_devices,
            # Risk indicator: high centrality + many connections
            'centrality_score': degree.get(user, 0) + betweenness.get(user, 0) * 10
        })

    df = pd.DataFrame(features)
    df.to_csv(os.path.join(DATA_DIR, 'graph_features.csv'), index=False)
    print(f'Graph features saved to data/graph_features.csv')

    return df

if __name__ == '__main__':
    compute_graph_features()

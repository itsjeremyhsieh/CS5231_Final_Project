import os

import networkx as nx
import matplotlib.pyplot as plt


def build_graph(events, has_threat):
    G = nx.DiGraph()
    for i, e in enumerate(events):
        G.add_node(e.id,
                   label=(e.template[:30] + "..." if len(e.template) > 30 else e.template),
                   color="red" if has_threat else "lightblue",
                   ts=e.timestamp.isoformat())
        if i > 0:
            G.add_edge(events[i - 1].id, e.id)
    return G


def draw_graph(G, postfix="", title="Provenance Graph", out_dir=None):
    pos = nx.spring_layout(G, seed=42)
    colors = [G.nodes[n]["color"] for n in G.nodes()]
    labels = {n: G.nodes[n]["label"] for n in G.nodes()}
    plt.figure(figsize=(12, 6))
    nx.draw(G, pos, node_color=colors, node_size=1000, with_labels=False)
    nx.draw_networkx_labels(G, pos, labels, font_size=8)
    nx.draw_networkx_edges(G, pos, arrows=True)
    plt.title(title)
    filename = f"provenance_graph_{postfix}.png"
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, filename)
    else:
        out_path = filename
    plt.savefig(out_path)
    plt.close()
    print(f"    Saved graph to {out_path}")
    return out_path

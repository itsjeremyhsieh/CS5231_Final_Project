import os
import textwrap

import networkx as nx
import matplotlib.pyplot as plt


def _short(s, length=40):
    if not s:
        return ""
    s = s.replace("\n", " ")
    if len(s) <= length:
        return s
    return s[:length - 3] + "..."


def build_graph(events, has_threat):
    G = nx.DiGraph()
    for i, e in enumerate(events):
        ts_short = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if hasattr(e, 'timestamp') else ""
        host = e.host or ""
        src = e.src_ip or ""
        tmpl = _short(e.template or "", length=50)
        msg = _short(e.message or "", length=80)

        # avoid duplicating the same content twice (template may equal message)
        tmpl_norm = (tmpl or "").strip().lower()
        msg_norm = (msg or "").strip().lower()
        template_part = tmpl if tmpl and tmpl_norm != msg_norm else None

        # create a multiline label: timestamp, host/src, template (if distinct), short message
        parts = [p for p in [ts_short, host or src, template_part, textwrap.fill(msg, width=40)] if p]
        label = "\n".join(parts)

        G.add_node(e.id,
                   label=label,
                   color="red" if has_threat else "lightblue",
                   ts=e.timestamp.isoformat() if hasattr(e, 'timestamp') else "",
                   host=host,
                   src_ip=src,
                   message=msg)
        if i > 0:
            G.add_edge(events[i - 1].id, e.id)
    return G


def draw_graph(G, postfix="", title="Provenance Graph", out_dir=None):
    """Draw the graph to a PNG with improved label readability.

    - Uses a spring layout with a fixed seed for reproducible layouts.
    - Computes a font size based on node count to avoid tiny text.
    - Draws label backgrounds (bbox) so labels remain readable over edges.
    """
    if G.number_of_nodes() == 0:
        raise ValueError("graph has no nodes")

    # Attempt to use Graphviz layouts for better non-overlapping placements when available.
    pos = None
    try:
        # prefer pygraphviz
        pos = nx.nx_agraph.graphviz_layout(G, prog="neato")
    except Exception:
        try:
            pos = nx.nx_pydot.graphviz_layout(G, prog="neato")
        except Exception:
            # fallback to spring layout with stronger repulsion and more iterations
            n_nodes = max(1, G.number_of_nodes())
            k = 0.8 * (1.0 + (n_nodes / 50.0))
            pos = nx.spring_layout(G, seed=42, k=k, iterations=250)

    # node colors and labels
    colors = [G.nodes[n].get("color", "lightblue") for n in G.nodes()]
    labels = {n: G.nodes[n].get("label", str(n)) for n in G.nodes()}

    # dynamic figure size and font sizing
    n = max(1, G.number_of_nodes())
    width = max(8, min(20, n * 0.8))
    height = max(6, min(20, n * 0.45))
    # simple stepwise font sizing: fewer nodes -> larger font
    if n <= 5:
        font_size = 12
        node_size = 1500
    elif n <= 15:
        font_size = 10
        node_size = 1100
    elif n <= 30:
        font_size = 8
        node_size = 800
    else:
        font_size = 6
        node_size = 450

    plt.figure(figsize=(width, height))

    # draw nodes and edges
    nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=node_size, linewidths=0.5, edgecolors="k")
    nx.draw_networkx_edges(G, pos, arrows=True, arrowstyle="-|>", arrowsize=12, width=1.0)

    # compute a center and push labels slightly outward from the center to reduce overlap
    xs = [xy[0] for xy in pos.values()]
    ys = [xy[1] for xy in pos.values()]
    center_x = sum(xs) / len(xs)
    center_y = sum(ys) / len(ys)

    # scalar to control how far labels are offset (larger graphs -> larger offset)
    offset_base = 0.05 * (1.0 + (G.number_of_nodes() / 40.0))

    for node, (x, y) in pos.items():
        lbl = labels.get(node, str(node))
        # vector from center to node
        vx = x - center_x
        vy = y - center_y
        # normalize
        mag = (vx * vx + vy * vy) ** 0.5
        if mag == 0:
            nx_off = 0
            ny_off = 0
        else:
            nx_off = (vx / mag) * offset_base
            ny_off = (vy / mag) * offset_base

        # place label slightly offset from the node to reduce overlapping labels
        plt.text(x + nx_off, y + ny_off,
                 lbl,
                 fontsize=font_size,
                 ha='center', va='center',
                 bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.95, linewidth=0.4))

    plt.title(title)
    plt.axis('off')
    plt.tight_layout()

    filename = f"provenance_graph_{postfix}.png"
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, filename)
    else:
        out_path = filename
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"    Saved graph to {out_path}")
    return out_path

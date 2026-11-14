"""Figures for ASN.1 narratives; domain operations remain in visible SQL."""

import matplotlib.pyplot as plt
import numpy as np
from vgi_notebooks import finish as finish_chart


def finish(fig, title, subtitle, filename):
    finish_chart(
        fig,
        title,
        subtitle,
        "Source: seven authored ASN.1 packets · VGI ASN.1 v0.4.0 · structural parsing only",
        name=filename.removesuffix(".png"),
    )


def plot_lengths(lengths, TRIM_BYTES, byte_unit):
    fig, ax = plt.subplots(figsize=(11.5, 7.5))
    y = np.arange(len(lengths))
    ax.barh(y - 0.18, lengths.raw_bytes, height=0.32, color="#4a6f9b", label="Raw bytes")
    valid = lengths.normalized_bytes.notna()
    ax.barh(
        y[valid] + 0.18,
        lengths.loc[valid, "normalized_bytes"].astype(float),
        height=0.32,
        color="#2a8066",
        label="Normalized bytes",
    )
    for i, row in lengths.iterrows():
        ax.text(row.raw_bytes + 0.25, i - 0.18, str(row.raw_bytes), va="center", fontsize=10)
        if row.well_formed:
            ax.text(
                float(row.normalized_bytes) + 0.25,
                i + 0.18,
                str(int(row.normalized_bytes)),
                va="center",
                fontsize=10,
                color="#21664f",
            )
        else:
            ax.text(0.5, i + 0.18, "unavailable — malformed", va="center", fontsize=10, color="#a34b36")
    ax.set_yticks(y, lengths.label)
    ax.invert_yaxis()
    ax.set_xlabel("Packet size (bytes)")
    ax.set_xlim(0, float(lengths.raw_bytes.max()) + 4)
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower right")
    finish(
        fig,
        "Length framing changes; primitive content survives",
        f"Seven synthetic packets · {TRIM_BYTES} {byte_unit} removed from the indefinite-length packet",
        f"lengths-trim-{TRIM_BYTES}.png",
    )


def plot_groups(groups, TRIM_BYTES):
    fig, ax = plt.subplots(figsize=(11.5, 6.2))
    y = np.arange(len(groups))
    labels = [f"Value group {i + 1}\n{row.decoded_values}" for i, row in groups.iterrows()]
    ax.barh(y - 0.18, groups.raw_encodings, height=0.32, color="#4a6f9b", label="Raw encodings")
    ax.barh(y + 0.18, groups.normalized_encodings, height=0.32, color="#2a8066", label="Normalized encodings")
    for i, row in groups.iterrows():
        ax.text(row.raw_encodings + 0.08, i - 0.18, str(row.raw_encodings), va="center")
        ax.text(row.normalized_encodings + 0.08, i + 0.18, str(row.normalized_encodings), va="center")
    ax.set_yticks(y, labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("Distinct byte encodings (count)")
    ax.set_xlim(0, int(groups.raw_encodings.max()) + 1)
    ax.set_xticks(range(int(groups.raw_encodings.max()) + 2))
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower right")
    finish(
        fig,
        "One decoded value group can retain several encodings",
        "Malformed inputs excluded · byte identity measured directly, without relying on hash uniqueness",
        f"groups-trim-{TRIM_BYTES}.png",
    )


def plot_inspection(nodes, inventory, include_unknown):
    fig, axes = plt.subplots(1, 2, figsize=(12.6, 6.2), gridspec_kw={"width_ratios": [1.6, 1]})
    y = np.arange(len(nodes))
    axes[0].barh(y, nodes.header_bytes, color="#bc8a3e", label="Node header")
    axes[0].barh(y, nodes.content_bytes, left=nodes.header_bytes, color="#267358", label="Node content")
    axes[0].set_yticks(y, nodes.path + " · " + nodes.tag)
    axes[0].invert_yaxis()
    axes[0].set(xlabel="Bytes within each node · nested rows overlap", xlim=(0, 23))
    for i, row in nodes.iterrows():
        axes[0].text(
            row.header_bytes + row.content_bytes + 0.3,
            i,
            str(int(row.header_bytes + row.content_bytes)),
            va="center",
        )
    axes[0].legend(loc="lower right", fontsize=9)
    counts = [int(inventory.registry_name.notna().sum()), int(inventory.registry_name.isna().sum())]
    bars = axes[1].barh([0, 1], counts, color=["#267358", "#bc8a3e"], height=0.45)
    axes[1].bar_label(bars, padding=5)
    axes[1].set(
        yticks=[0, 1],
        yticklabels=["Named in registry", "Unknown to registry"],
        xlabel="OID occurrences in selected packets",
        xlim=(0, 2.1),
        xticks=[0, 1, 2],
    )
    axes[1].invert_yaxis()
    for ax in axes:
        ax.grid(axis="y", visible=False)
    finish_chart(
        fig,
        "Structure identifies fields; the registry supplies names",
        f"Left: intact known-OID packet · right: include unknown packet = {include_unknown}",
        "Source: authored ASN.1 packets + bundled OID registry · VGI ASN.1 v0.4.0",
        name=f"inspection-unknown-{include_unknown}",
    )


def plot_armor(blocks):
    fig, ax = plt.subplots(figsize=(11.5, 5.2))
    y = np.arange(len(blocks))
    colors = ["#267358" if ok else "#b65b3d" for ok in blocks.well_formed]
    bars = ax.barh(y, blocks.body_bytes, color=colors, height=0.48)
    ax.bar_label(bars, padding=5)
    ax.set_yticks(y, [f"Block {int(r.idx)} · {r.label}" for r in blocks.itertuples()])
    ax.invert_yaxis()
    ax.set(xlabel="Decoded body bytes · labels alone do not validate these bodies", xlim=(0, 9))
    ax.grid(axis="y", visible=False)
    for i, row in blocks.iterrows():
        ax.text(
            5.9,
            i,
            "BER structure parsed" if row.well_formed else str(row.error_kind),
            va="center",
            fontsize=10,
            color=colors[i],
        )
    finish_chart(
        fig,
        "A PEM header is a label, not a parsed object type",
        "Three base64-decodable blocks · two valid ASN.1 bodies · one malformed body",
        "Source: authored teaching armor and integer SEQUENCEs · VGI ASN.1 v0.4.0",
        name="pem-body-triage",
    )

"""
V-NAPE Visualization Utilities

Provides visualization capabilities for:
- Protocol traces and events
- Policy structures
- Metrics and performance data
- Protocol state machines
"""

import html
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class PlotConfig:
    """Configuration for plots."""

    width: int = 800
    height: int = 400
    title: str = ""
    x_label: str = ""
    y_label: str = ""
    show_legend: bool = True
    theme: str = "light"
    color_scheme: list[str] = field(
        default_factory=lambda: [
            "#4285f4",  # Blue
            "#ea4335",  # Red
            "#fbbc04",  # Yellow
            "#34a853",  # Green
            "#ff6d01",  # Orange
            "#46bdc6",  # Teal
            "#7baaf7",  # Light blue
            "#f07b72",  # Light red
        ]
    )


class TraceVisualizer:
    """Visualizer for protocol traces."""

    def __init__(self, config: PlotConfig | None = None):
        self.config = config or PlotConfig()

    def timeline(
        self,
        events: list[dict[str, Any]],
        highlight_violations: bool = True,
    ) -> str:
        """Generate an HTML timeline of trace events."""
        if not events:
            return "<p>No events to display</p>"

        html_content = [
            f'<div class="trace-timeline" style="font-family: sans-serif; max-width: {self.config.width}px;">',
            f'<h3>{html.escape(self.config.title or "Trace Timeline")}</h3>',
            '<div class="timeline-container" style="position: relative; margin-left: 100px;">',
        ]

        for i, event in enumerate(events):
            timestamp = event.get("timestamp", "")
            event_name = event.get("name", event.get("event_name", "Unknown"))
            is_violation = event.get("is_violation", False)

            color = "#ea4335" if (is_violation and highlight_violations) else "#4285f4"

            html_content.append(
                f"""
                <div class="timeline-event" style="position: relative; padding: 10px 0; border-left: 2px solid #ccc; padding-left: 20px; margin-left: 0;">
                    <div class="event-dot" style="position: absolute; left: -6px; top: 15px; width: 10px; height: 10px; border-radius: 50%; background: {color};"></div>
                    <div class="event-time" style="position: absolute; left: -110px; top: 10px; width: 100px; text-align: right; font-size: 12px; color: #666;">{html.escape(str(timestamp))}</div>
                    <div class="event-content">
                        <strong style="color: {color};">{html.escape(event_name)}</strong>
                        <div style="font-size: 12px; color: #666;">{html.escape(json.dumps(event.get("args", {}), default=str)[:100])}</div>
                    </div>
                </div>
            """
            )

        html_content.append("</div></div>")
        return "\n".join(html_content)

    def sequence_diagram(
        self,
        events: list[dict[str, Any]],
        participants: list[str] | None = None,
    ) -> str:
        """Generate a Mermaid sequence diagram."""
        if not events:
            return "sequenceDiagram\n    Note over System: No events"

        if participants is None:
            participants = list(
                set(event.get("source", "System") for event in events)
                | set(event.get("target", "System") for event in events)
            )

        lines = ["sequenceDiagram"]
        for p in participants:
            lines.append(f"    participant {p}")

        for event in events:
            source = event.get("source", "System")
            target = event.get("target", source)
            name = event.get("name", event.get("event_name", "event"))

            if source == target:
                lines.append(f"    {source}->>+{source}: {name}")
            else:
                lines.append(f"    {source}->>+{target}: {name}")

        return "\n".join(lines)


class PolicyVisualizer:
    """Visualizer for MFOTL policies."""

    def __init__(self, config: PlotConfig | None = None):
        self.config = config or PlotConfig()

    def parse_tree(self, policy: str) -> str:
        """Generate an HTML parse tree visualization of a policy."""
        # Simplified tokenization for visualization
        tokens = self._tokenize(policy)
        tree = self._build_tree(tokens)
        return self._render_tree(tree)

    def _tokenize(self, policy: str) -> list[str]:
        """Tokenize a policy string."""
        # Replace operators with spaced versions
        policy = policy.replace("□", " □ ").replace("◇", " ◇ ")
        policy = policy.replace("∀", " ∀ ").replace("∃", " ∃ ")
        policy = policy.replace("→", " → ").replace("∧", " ∧ ").replace("∨", " ∨ ")
        policy = policy.replace("¬", " ¬ ")
        policy = policy.replace("(", " ( ").replace(")", " ) ")
        policy = policy.replace("[", " [ ").replace("]", " ] ")
        policy = policy.replace(",", " , ")
        return [t for t in policy.split() if t]

    def _build_tree(self, tokens: list[str]) -> dict[str, Any]:
        """Build a simple tree structure from tokens."""
        return {
            "type": "policy",
            "content": " ".join(tokens),
            "children": [],
        }

    def _render_tree(self, tree: dict[str, Any], depth: int = 0) -> str:
        """Render tree as HTML."""
        indent = "  " * depth
        html_parts = [
            f'{indent}<div class="policy-node" style="margin-left: {depth * 20}px; padding: 5px; border-left: 2px solid #4285f4;">',
            f'{indent}  <code>{html.escape(tree.get("content", ""))}</code>',
        ]

        for child in tree.get("children", []):
            html_parts.append(self._render_tree(child, depth + 1))

        html_parts.append(f"{indent}</div>")
        return "\n".join(html_parts)

    def policy_card(self, policy: str, name: str = "", status: str = "active") -> str:
        """Generate an HTML card for a policy."""
        status_color = {
            "active": "#34a853",
            "violated": "#ea4335",
            "pending": "#fbbc04",
            "disabled": "#9aa0a6",
        }.get(status.lower(), "#4285f4")

        return f"""
        <div class="policy-card" style="border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin: 8px 0; max-width: 500px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <strong>{html.escape(name or 'Policy')}</strong>
                <span style="background: {status_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">{html.escape(status)}</span>
            </div>
            <code style="display: block; background: #f5f5f5; padding: 8px; border-radius: 4px; font-size: 14px; word-break: break-all;">
                {html.escape(policy)}
            </code>
        </div>
        """


class MetricsVisualizer:
    """Visualizer for metrics data."""

    def __init__(self, config: PlotConfig | None = None):
        self.config = config or PlotConfig()

    def bar_chart(
        self,
        data: dict[str, float],
        title: str = "",
    ) -> str:
        """Generate an HTML/CSS bar chart."""
        if not data:
            return "<p>No data to display</p>"

        max_value = max(data.values()) if data.values() else 1

        html_parts = [
            f'<div class="bar-chart" style="font-family: sans-serif; max-width: {self.config.width}px;">',
            f"<h4>{html.escape(title or self.config.title)}</h4>",
        ]

        for i, (label, value) in enumerate(data.items()):
            width_pct = (value / max_value) * 100 if max_value > 0 else 0
            color = self.config.color_scheme[i % len(self.config.color_scheme)]

            html_parts.append(
                f"""
                <div style="display: flex; align-items: center; margin: 8px 0;">
                    <span style="width: 120px; font-size: 14px;">{html.escape(str(label))}</span>
                    <div style="flex: 1; background: #eee; border-radius: 4px; height: 24px; margin: 0 8px;">
                        <div style="width: {width_pct}%; background: {color}; height: 100%; border-radius: 4px;"></div>
                    </div>
                    <span style="width: 60px; text-align: right; font-size: 14px;">{value:.2f}</span>
                </div>
            """
            )

        html_parts.append("</div>")
        return "\n".join(html_parts)

    def line_chart(
        self,
        data: list[tuple[datetime, float]],
        title: str = "",
    ) -> str:
        """Generate an SVG line chart."""
        if not data:
            return "<p>No data to display</p>"

        width = self.config.width
        height = self.config.height
        padding = 50

        # Calculate scales
        times = [d[0] for d in data]
        values = [d[1] for d in data]

        min_val, max_val = min(values), max(values)
        val_range = max_val - min_val if max_val != min_val else 1

        # Generate points
        points = []
        for i, (t, v) in enumerate(data):
            x = (
                padding + (i / (len(data) - 1)) * (width - 2 * padding)
                if len(data) > 1
                else width / 2
            )
            y = height - padding - ((v - min_val) / val_range) * (height - 2 * padding)
            points.append(f"{x},{y}")

        polyline_points = " ".join(points)

        svg = f"""
        <svg width="{width}" height="{height}" style="font-family: sans-serif;">
            <text x="{width/2}" y="20" text-anchor="middle" font-size="14" font-weight="bold">{html.escape(title or self.config.title)}</text>
            
            <!-- Axes -->
            <line x1="{padding}" y1="{height - padding}" x2="{width - padding}" y2="{height - padding}" stroke="#ccc" stroke-width="1"/>
            <line x1="{padding}" y1="{padding}" x2="{padding}" y2="{height - padding}" stroke="#ccc" stroke-width="1"/>
            
            <!-- Y-axis labels -->
            <text x="{padding - 5}" y="{height - padding}" text-anchor="end" font-size="10">{min_val:.1f}</text>
            <text x="{padding - 5}" y="{padding + 5}" text-anchor="end" font-size="10">{max_val:.1f}</text>
            
            <!-- Data line -->
            <polyline points="{polyline_points}" fill="none" stroke="{self.config.color_scheme[0]}" stroke-width="2"/>
            
            <!-- Data points -->
            {"".join(f'<circle cx="{p.split(",")[0]}" cy="{p.split(",")[1]}" r="4" fill="{self.config.color_scheme[0]}"/>' for p in points[:50])}
        </svg>
        """
        return svg

    def gauge(
        self,
        value: float,
        max_value: float = 100,
        title: str = "",
        thresholds: dict[float, str] | None = None,
    ) -> str:
        """Generate an SVG gauge chart."""
        if thresholds is None:
            thresholds = {0.33: "#34a853", 0.66: "#fbbc04", 1.0: "#ea4335"}

        # Determine color based on thresholds
        ratio = value / max_value if max_value > 0 else 0
        color = "#4285f4"
        for threshold, c in sorted(thresholds.items()):
            if ratio <= threshold:
                color = c
                break

        # Calculate arc
        angle = ratio * 180

        return f"""
        <div style="text-align: center; max-width: 200px;">
            <svg width="200" height="120" viewBox="0 0 200 120">
                <!-- Background arc -->
                <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#eee" stroke-width="15"/>
                
                <!-- Value arc -->
                <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="{color}" stroke-width="15"
                      stroke-dasharray="{angle * 1.4}, 252" stroke-linecap="round"/>
                
                <!-- Value text -->
                <text x="100" y="90" text-anchor="middle" font-size="24" font-weight="bold">{value:.1f}</text>
                <text x="100" y="110" text-anchor="middle" font-size="12" fill="#666">/ {max_value:.0f}</text>
            </svg>
            <div style="font-size: 14px; font-weight: bold;">{html.escape(title)}</div>
        </div>
        """


class ProtocolStateVisualizer:
    """Visualizer for protocol state machines."""

    def __init__(self, config: PlotConfig | None = None):
        self.config = config or PlotConfig()

    def state_diagram(
        self,
        states: list[str],
        transitions: list[tuple[str, str, str]],  # (from, to, label)
        current_state: str | None = None,
    ) -> str:
        """Generate a Mermaid state diagram."""
        lines = ["stateDiagram-v2"]

        # Add state definitions
        for state in states:
            if state == current_state:
                lines.append(f"    {state}: {state} 🔵")
            else:
                lines.append(f"    {state}")

        # Add transitions
        for from_state, to_state, label in transitions:
            if label:
                lines.append(f"    {from_state} --> {to_state}: {label}")
            else:
                lines.append(f"    {from_state} --> {to_state}")

        return "\n".join(lines)

    def state_table(
        self,
        states: list[dict[str, Any]],
    ) -> str:
        """Generate an HTML table of states."""
        html_parts = [
            '<table style="border-collapse: collapse; width: 100%; font-family: sans-serif;">',
            "<thead>",
            '<tr style="background: #f5f5f5;">',
            '<th style="border: 1px solid #ddd; padding: 8px;">State</th>',
            '<th style="border: 1px solid #ddd; padding: 8px;">Description</th>',
            '<th style="border: 1px solid #ddd; padding: 8px;">Security Level</th>',
            '<th style="border: 1px solid #ddd; padding: 8px;">Status</th>',
            "</tr>",
            "</thead>",
            "<tbody>",
        ]

        for state in states:
            name = state.get("name", "Unknown")
            description = state.get("description", "")
            security_level = state.get("security_level", "normal")
            is_current = state.get("is_current", False)

            level_color = {
                "critical": "#ea4335",
                "high": "#ff6d01",
                "normal": "#4285f4",
                "low": "#34a853",
            }.get(security_level.lower(), "#4285f4")

            row_style = "background: #e8f0fe;" if is_current else ""

            html_parts.append(
                f"""
                <tr style="{row_style}">
                    <td style="border: 1px solid #ddd; padding: 8px;"><strong>{html.escape(name)}</strong></td>
                    <td style="border: 1px solid #ddd; padding: 8px;">{html.escape(description)}</td>
                    <td style="border: 1px solid #ddd; padding: 8px;"><span style="color: {level_color};">{html.escape(security_level)}</span></td>
                    <td style="border: 1px solid #ddd; padding: 8px;">{"🔵 Current" if is_current else ""}</td>
                </tr>
            """
            )

        html_parts.extend(["</tbody>", "</table>"])
        return "\n".join(html_parts)


# Convenience functions
def plot_enforcement_timeline(
    decisions: list[dict[str, Any]],
    config: PlotConfig | None = None,
) -> str:
    """Plot enforcement decisions over time."""
    viz = TraceVisualizer(config)
    events = [
        {
            "timestamp": d.get("timestamp", ""),
            "name": d.get("action", "Unknown"),
            "is_violation": d.get("action", "").lower() in ["block", "terminate"],
            "args": {"policy": d.get("policy", ""), "confidence": d.get("confidence", 0)},
        }
        for d in decisions
    ]
    return viz.timeline(events, highlight_violations=True)


def plot_quantum_risk_evolution(
    risk_scores: list[tuple[datetime, float]],
    config: PlotConfig | None = None,
) -> str:
    """Plot quantum risk scores over time."""
    config = config or PlotConfig(title="Quantum Risk Evolution", y_label="Risk Score")
    viz = MetricsVisualizer(config)
    return viz.line_chart(risk_scores, title=config.title)


def plot_verification_coverage(
    verified: int,
    total: int,
    config: PlotConfig | None = None,
) -> str:
    """Plot verification coverage gauge."""
    config = config or PlotConfig()
    viz = MetricsVisualizer(config)
    coverage = (verified / total * 100) if total > 0 else 0
    return viz.gauge(
        coverage,
        max_value=100,
        title="Verification Coverage",
        thresholds={0.5: "#ea4335", 0.8: "#fbbc04", 1.0: "#34a853"},
    )


def export_to_html(
    content: str | list[str],
    output_path: str | Path,
    title: str = "V-NAPE Visualization",
) -> None:
    """Export visualization content to an HTML file."""
    if isinstance(content, list):
        content = "\n".join(content)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #fafafa;
        }}
        h1 {{ color: #333; }}
        .visualization-container {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin: 20px 0;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <script>mermaid.initialize({{startOnLoad:true}});</script>
</head>
<body>
    <h1>{html.escape(title)}</h1>
    <div class="visualization-container">
        {content}
    </div>
</body>
</html>"""

    Path(output_path).write_text(html_doc)

from aegis import charts


def bars():
    return [
        charts.StackedBar("10-01", {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 9, "LOW": 3}),
        charts.StackedBar("10-02", {"CRITICAL": 0, "HIGH": 4, "MEDIUM": 7, "LOW": 1}),
    ]


def test_empty_input_renders_an_empty_state():
    assert "chart-empty" in charts.stacked_bars([])
    assert "chart-empty" in charts.horizontal_bars([])


def test_stacked_bars_emit_one_rect_per_non_zero_segment():
    svg = charts.stacked_bars(bars())
    assert svg.count("<rect") == 7  # 4 severities + 3 (10-02 has no criticals)
    assert "<svg" in svg and "</svg>" in svg
    assert 'role="img"' in svg


def test_every_segment_carries_a_text_label_for_accessibility():
    svg = charts.stacked_bars(bars())
    # Identity is never colour-alone: each segment has a <title> and a tooltip.
    assert svg.count("<title>") == svg.count("data-tip=")
    assert "Critical: 2" in svg


def test_horizontal_bars_are_sorted_by_total():
    unsorted = [
        charts.StackedBar("small", {"LOW": 1}),
        charts.StackedBar("large", {"HIGH": 50}),
    ]
    svg = charts.horizontal_bars(unsorted)
    assert svg.index("large") < svg.index("small")


def test_chart_values_are_escaped():
    svg = charts.stacked_bars([charts.StackedBar('<script>"x"', {"HIGH": 1})])
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg


def test_axis_ticks_are_round_numbers():
    assert charts._nice_ticks(97)[-1] >= 97
    assert charts._nice_ticks(0) == [0, 1]
    assert all(isinstance(t, int) for t in charts._nice_ticks(1234))


def test_sparkline_needs_two_points():
    assert "spark-empty" in charts.sparkline([5])
    assert "<polyline" in charts.sparkline([1, 5, 3])


def test_legend_names_every_severity():
    legend = charts.legend()
    for name in ("Critical", "High", "Medium", "Low"):
        assert name in legend

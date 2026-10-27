"""Tests for the node_manager utilities."""

import sys
import pathlib
# Add project root to sys.path so that top‑level packages (node_manager) can be imported
project_root = pathlib.Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.append(str(project_root))

from node_manager import manager as node_mgr


def test_list_nodes_contains_expected_ids():
    nodes = node_mgr.list_nodes()
    ids = {n["id"] for n in nodes}
    expected = {"bitcoin", "lnd", "geth"}
    assert expected.issubset(ids)


def test_get_node_config_returns_none_for_unknown():
    cfg = node_mgr.get_node_config("unknown")
    assert cfg is None



def test_list_nodes_contains_expected_ids():
    nodes = node_mgr.list_nodes()
    ids = {n["id"] for n in nodes}
    expected = {"bitcoin", "lnd", "geth"}
    assert expected.issubset(ids)


def test_get_node_config_returns_none_for_unknown():
    cfg = node_mgr.get_node_config("unknown")
    assert cfg is None

"""Inventory collectors: services, startup, drivers, listening ports, DNS."""

import sys

import pytest

from backend.app.collectors.inventory import (
    INVENTORY_COLLECTORS,
    collect_dns_config,
    collect_drivers,
    collect_listening_ports,
    collect_services,
    collect_startup_entries,
)


@pytest.fixture
def linux_root(tmp_path):
    """A miniature Linux filesystem with known services, cron jobs, modules and resolvers."""

    def write(rel, text):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    write(
        "etc/systemd/system/backdoor.service",
        "[Unit]\nDescription=Totally Normal Service\n[Service]\nExecStart=/tmp/.x/run.sh\nUser=nobody\n",
    )
    write("lib/systemd/system/ssh.service", "[Unit]\nDescription=OpenSSH server\n[Service]\nExecStart=/usr/sbin/sshd -D\n")
    write("etc/systemd/system/multi-user.target.wants/backdoor.service", "")
    write("etc/crontab", "SHELL=/bin/sh\n# comment\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    write("etc/cron.d/updater", "@reboot root /opt/updater/update.sh\n")
    write("var/spool/cron/crontabs/alice", "*/5 * * * * /home/alice/bin/beacon.sh\n")
    write("home/alice/.config/autostart/sync.desktop", "[Desktop Entry]\nName=Sync\nExec=/home/alice/bin/sync\n")
    write("etc/rc.local", "#!/bin/sh\n/usr/local/bin/firewall-up\nexit 0\n")
    write("proc/modules", "e1000 147456 0 - Live 0x0000000000000000\nrootkit_mod 16384 1 e1000, Live 0x0 (OE)\n")
    write("sys/module/rootkit_mod/taint", "OE\n")
    write("etc/resolv.conf", "# generated\nnameserver 10.0.0.53\nnameserver 1.1.1.1\nsearch corp.local\n")
    write("etc/hosts", "127.0.0.1 localhost\n203.0.113.9 update.microsoft.com # suspicious\n")
    return str(tmp_path)


def test_linux_services_parse_unit_files_and_enablement(linux_root):
    result = collect_services(root_dir=linux_root, platform_name="Linux")
    assert result["collection_status"] == "collected"
    by_name = {s["name"]: s for s in result["items"]}
    backdoor = by_name["backdoor.service"]
    assert backdoor["binary_path"] == "/tmp/.x/run.sh"
    assert backdoor["run_as"] == "nobody"
    assert backdoor["start_mode"] == "enabled"
    assert by_name["ssh.service"]["start_mode"] == "static_or_disabled"


def test_linux_startup_covers_cron_autostart_and_rc_local(linux_root):
    result = collect_startup_entries(root_dir=linux_root, platform_name="Linux")
    sources = {item["source"] for item in result["items"]}
    assert sources == {"cron", "xdg_autostart", "rc_local"}
    commands = [item["command"] for item in result["items"]]
    assert "/opt/updater/update.sh" in commands
    assert "/home/alice/bin/sync" in commands
    assert "/usr/local/bin/firewall-up" in commands
    beacon = next(i for i in result["items"] if i["name"] == "alice")
    assert beacon["command"] == "/home/alice/bin/beacon.sh"
    assert beacon["run_as"] is None
    hourly = next(i for i in result["items"] if "run-parts" in (i["command"] or ""))
    assert hourly["schedule"] == "17 * * * *"
    assert hourly["run_as"] == "root"
    reboot = next(i for i in result["items"] if i["command"] == "/opt/updater/update.sh")
    assert reboot["schedule"] == "@reboot"
    assert not any("SHELL=" in (c or "") for c in commands)


def test_linux_modules_report_taint_flags(linux_root):
    result = collect_drivers(root_dir=linux_root, platform_name="Linux")
    mods = {m["name"]: m for m in result["items"]}
    assert mods["e1000"]["size_bytes"] == 147456
    assert mods["e1000"]["unsigned"] is False
    assert mods["rootkit_mod"]["unsigned"] is True
    assert mods["rootkit_mod"]["out_of_tree"] is True
    assert mods["rootkit_mod"]["used_by"] == ["e1000"]


def test_missing_proc_modules_is_an_error_not_an_empty_list(tmp_path):
    result = collect_drivers(root_dir=str(tmp_path), platform_name="Linux")
    assert result["collection_status"] == "error"
    assert result["errors"]


def test_linux_dns_reads_resolvers_and_hosts(linux_root):
    result = collect_dns_config(root_dir=linux_root, platform_name="Linux")
    servers = [i["value"] for i in result["items"] if i["kind"] == "nameserver"]
    assert servers == ["10.0.0.53", "1.1.1.1"]
    hosts = [i for i in result["items"] if i["kind"] == "hosts_entry"]
    assert any("update.microsoft.com" in h["names"] for h in hosts)


def test_macos_drivers_are_reported_unsupported():
    result = collect_drivers(platform_name="Darwin")
    assert result["collection_status"] == "unsupported"
    assert "no process execution" in result["reason"]


def test_unknown_platform_is_unsupported_everywhere():
    for fn in (collect_services, collect_startup_entries, collect_dns_config):
        assert fn(platform_name="Plan9")["collection_status"] == "unsupported"


def test_listening_ports_have_the_contract_shape():
    result = collect_listening_ports()
    assert result["collector"] == "listening_ports"
    assert result["collection_status"] in ("collected", "partial", "denied")
    for item in result["items"]:
        assert item["protocol"] in ("TCP", "UDP")
        assert isinstance(item["exposed"], bool)


@pytest.mark.parametrize("name", sorted(INVENTORY_COLLECTORS))
def test_every_collector_runs_on_this_host_and_never_raises(name):
    result = INVENTORY_COLLECTORS[name]()
    assert result["read_only"] is True
    assert result["collection_status"] in ("collected", "partial", "unsupported", "denied", "error")
    assert result["count"] == len(result["items"])


@pytest.mark.skipif(sys.platform != "win32", reason="Service Control Manager and registry are Windows-only")
def test_windows_live_inventory_finds_services_and_drivers():
    assert collect_services()["count"] > 0
    drivers = collect_drivers()
    assert drivers["count"] > 0
    assert {d["driver_type"] for d in drivers["items"]} <= {"kernel_driver", "file_system_driver"}

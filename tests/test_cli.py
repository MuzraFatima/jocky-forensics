"""`jocky compile` prints summaries, compiler stages as JSON, and coded errors with hints."""

import json

from backend.app.cli import main


def _script(tmp_path, text):
    path = tmp_path / "case.jocky"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_summary_marks_unsupported_operations(tmp_path, capsys):
    path = _script(tmp_path, 'CASE "c"\nTARGET "h"\nCOLLECT SYSTEM\nCOLLECT REGISTRY\n')
    assert main(["compile", path, "--platform", "linux"]) == 0
    out = capsys.readouterr().out
    assert "Platform:   LINUX" in out
    assert "line 4: COLLECT REGISTRY  [unsupported" in out


def test_emit_ir_prints_json(tmp_path, capsys):
    path = _script(tmp_path, 'investigation "c" { target "h" collect system }')
    assert main(["compile", path, "--emit", "ir"]) == 0
    ir = json.loads(capsys.readouterr().out)
    assert ir["version"] == "2.0"
    assert ir["operations"][0]["capability"] == "COLLECT_SYSTEM"


def test_emit_tokens_and_backend(tmp_path, capsys):
    path = _script(tmp_path, 'CASE "c"\nTARGET "h"\nCOLLECT SYSTEM\n')
    assert main(["compile", path, "--emit", "tokens"]) == 0
    tokens = json.loads(capsys.readouterr().out)
    assert tokens[0] == {"type": "CASE", "value": "CASE", "line": 1, "column": 1}

    assert main(["compile", path, "--emit", "backend", "--platform", "windows"]) == 0
    assert json.loads(capsys.readouterr().out)["platform"] == "WINDOWS"


def test_errors_show_code_and_hint(tmp_path, capsys):
    path = _script(tmp_path, 'CASE "c"\nTARGET "h"\nCOLECT SYSTEM\n')
    assert main(["compile", path]) == 1
    err = capsys.readouterr().err
    assert "JKY205" in err
    assert "Hint: Did you mean 'COLLECT'?" in err


def test_missing_file(tmp_path, capsys):
    assert main(["compile", str(tmp_path / "nope.jocky")]) == 1
    assert "not found" in capsys.readouterr().err


from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = Path(__file__).parent
PUBLIC_DIR = BASE_DIR / "public"
EDITOR_DIR = BASE_DIR / "editor"
DATA_DIR = PUBLIC_DIR / "data"
BACKUP_DIR = BASE_DIR / "backups"
RISK_TABLE_REGISTRY_PATH = DATA_DIR / "riskTables.json"
RISK_TABLE_DIR = DATA_DIR / "riskTables"
SAFE_RISK_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")

app = Flask(__name__, static_folder=None)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def backup_path_for(path: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if path.parent == RISK_TABLE_DIR:
        backup_dir = BACKUP_DIR / "riskTables"
    else:
        backup_dir = BACKUP_DIR
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"{path.stem}.{timestamp}.bak"
    suffix = 1
    while backup_path.exists():
        backup_path = backup_dir / f"{path.stem}.{timestamp}.{suffix}.bak"
        suffix += 1
    return backup_path


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, backup_path_for(path))
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def is_object(value: Any) -> bool:
    return isinstance(value, dict)


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def validate_score(errors: list[str], value: Any, path: str) -> None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        errors.append(f"{path} must be a number.")
        return
    require(errors, 1 <= number <= 5, f"{path} must be between 1 and 5.")


def validate_text_list(errors: list[str], value: Any, path: str) -> None:
    require(errors, isinstance(value, list), f"{path} must be a list.")
    if not isinstance(value, list):
        return
    for index, item in enumerate(value):
        require(errors, isinstance(item, str), f"{path}[{index}] must be text.")


def validate_risk_id(value: Any, label: str = "Risk Analysis ID") -> list[str]:
    risk_id = str(value or "").strip()
    errors: list[str] = []
    require(errors, bool(risk_id), f"{label} is required.")
    require(errors, bool(SAFE_RISK_ID_PATTERN.fullmatch(risk_id)), f"{label} may contain only letters, numbers, underscores, or hyphens and must start with a letter.")
    return errors


def validate_risk_registry(data: Any) -> list[str]:
    errors: list[str] = []
    require(errors, is_object(data), "riskTables must be an object.")
    if not is_object(data):
        return errors
    for section_name in ("home", "reference", "search"):
        section = data.get(section_name)
        section_path = f"riskTables.{section_name}"
        require(errors, is_object(section), f"{section_path} must be an object.")
        if not is_object(section):
            continue
        require(errors, isinstance(section.get("title"), str) and bool(section.get("title", "").strip()), f"{section_path}.title is required.")
        validate_text_list(errors, section.get("intro"), f"{section_path}.intro")
    reference = data.get("reference")
    if is_object(reference):
        validate_text_list(errors, reference.get("items"), "riskTables.reference.items")
    categories = data.get("categories")
    require(errors, isinstance(categories, list) and len(categories) > 0, "riskTables.categories must be a non-empty list.")
    if not isinstance(categories, list):
        return errors
    seen_categories: set[str] = set()
    seen_ids: set[str] = set()
    for category_index, category in enumerate(categories):
        category_path = f"riskTables.categories[{category_index}]"
        require(errors, is_object(category), f"{category_path} must be an object.")
        if not is_object(category):
            continue
        category_id = category.get("id")
        category_errors = validate_risk_id(category_id, "Category ID")
        errors.extend(f"{category_path}: {message}" for message in category_errors)
        if isinstance(category_id, str):
            if category_id in seen_categories:
                errors.append(f"riskTables.categories contains duplicate id {category_id}.")
            seen_categories.add(category_id)
        require(errors, isinstance(category.get("title"), str) and bool(category.get("title", "").strip()), f"{category_path}.title is required.")
        require(errors, isinstance(category.get("description"), str), f"{category_path}.description must be text.")
        validate_text_list(errors, category.get("intro"), f"{category_path}.intro")
        analyses = category.get("analyses")
        require(errors, isinstance(analyses, list), f"{category_path}.analyses must be a list.")
        if not isinstance(analyses, list):
            continue
        for index, analysis in enumerate(analyses):
            item_path = f"{category_path}.analyses[{index}]"
            require(errors, is_object(analysis), f"{item_path} must be an object.")
            if not is_object(analysis):
                continue
            risk_id = analysis.get("id")
            require(errors, isinstance(risk_id, str) and bool(risk_id.strip()), f"{item_path}.id is required.")
            if not isinstance(risk_id, str):
                continue
            valid_id = bool(SAFE_RISK_ID_PATTERN.fullmatch(risk_id))
            require(errors, valid_id, f"{item_path}.id may contain only letters, numbers, underscores, or hyphens and must start with a letter.")
            if risk_id in seen_ids:
                errors.append(f"riskTables.categories contains duplicate Risk Analysis id {risk_id}.")
            seen_ids.add(risk_id)
            require(errors, isinstance(analysis.get("title"), str) and bool(analysis.get("title", "").strip()), f"{item_path}.title is required.")
            require(errors, isinstance(analysis.get("description"), str), f"{item_path}.description must be text.")
            require(errors, analysis.get("path") == f"riskTables/{risk_id}.json", f"{item_path}.path must reference riskTables/{risk_id}.json.")
            require(errors, analysis.get("link") == f"index.html?page=risk&service={risk_id}", f"{item_path}.link must reference the Risk Analysis.")
            validate_text_list(errors, analysis.get("intro"), f"{item_path}.intro")
            validate_text_list(errors, analysis.get("items"), f"{item_path}.items")
            if valid_id:
                require(errors, risk_table_path(risk_id).is_file(), f"riskTables/{risk_id}.json is missing.")
    return errors


def validate_risk_analysis_rows(data: Any, risk_id: str) -> list[str]:
    errors: list[str] = []
    require(errors, isinstance(data, list), f"riskTables.{risk_id} must be a list.")
    if not isinstance(data, list):
        return errors
    seen_ids: set[str] = set()
    for index, row in enumerate(data):
        path = f"riskTables.{risk_id}[{index}]"
        require(errors, is_object(row), f"{path} must be an object.")
        if not is_object(row):
            continue
        control_id = str(row.get("id") or "").strip()
        require(errors, bool(control_id), f"{path}.id is required.")
        if control_id in seen_ids:
            errors.append(f"riskTables.{risk_id} contains duplicate id {control_id}.")
        seen_ids.add(control_id)
        require(errors, isinstance(row.get("label"), str) and row["label"].strip(), f"{path}.label is required.")
        require(errors, row.get("default") in ("enabled", "disabled"), f"{path}.default must be enabled or disabled.")
        for group_key, factors in {
            "likelihood": ("exploitability", "exposure", "prevalence"),
            "impact": ("confidentiality", "integrity", "availability"),
        }.items():
            group = row.get(group_key)
            require(errors, is_object(group), f"{path}.{group_key} must be an object.")
            if not is_object(group):
                continue
            for factor in factors:
                validate_score(errors, group.get(factor), f"{path}.{group_key}.{factor}")
        validate_text_list(errors, row.get("pros"), f"{path}.pros")
        validate_text_list(errors, row.get("cons"), f"{path}.cons")
    return errors


def risk_table_path(risk_id: str) -> Path:
    if not SAFE_RISK_ID_PATTERN.fullmatch(risk_id):
        raise ValueError("Invalid Risk Analysis ID.")
    path = (RISK_TABLE_DIR / f"{risk_id}.json").resolve()
    root = RISK_TABLE_DIR.resolve()
    if not path.is_relative_to(root):
        raise ValueError("Invalid Risk Analysis path.")
    return path


def load_risk_registry() -> dict[str, Any]:
    return read_json(RISK_TABLE_REGISTRY_PATH)


def find_risk_category_entry(registry: dict[str, Any], category_id: str) -> dict[str, Any] | None:
    categories = registry.get("categories") if is_object(registry) else []
    if not isinstance(categories, list):
        return None
    for category in categories:
        if is_object(category) and category.get("id") == category_id:
            return category
    return None


def find_risk_analysis_entry(registry: dict[str, Any], risk_id: str) -> dict[str, Any] | None:
    categories = registry.get("categories") if is_object(registry) else []
    if not isinstance(categories, list):
        return None
    for category in categories:
        if not is_object(category):
            continue
        analyses = category.get("analyses")
        if not isinstance(analyses, list):
            continue
        for analysis in analyses:
            if is_object(analysis) and analysis.get("id") == risk_id:
                return analysis
    return None


def validate_create_risk_payload(payload: Any, registry: dict[str, Any]) -> tuple[list[str], str, list[dict[str, Any]]]:
    errors: list[str] = []
    if not is_object(payload):
        return ["Request body must be JSON."], "", []
    risk_id = str(payload.get("serviceId") or "").strip()
    category_id = str(payload.get("categoryId") or "").strip()
    title = payload.get("title")
    description = payload.get("description")
    controls = payload.get("controls")
    errors.extend(validate_risk_id(risk_id))
    require(errors, bool(category_id), "Category is required.")
    require(errors, find_risk_category_entry(registry, category_id) is not None, "Unknown Risk Analysis category: " + category_id)
    if find_risk_analysis_entry(registry, risk_id):
        errors.append(f'Risk Analysis "{risk_id}" already exists.')
    require(errors, isinstance(title, str) and bool(title.strip()), "Title is required.")
    require(errors, isinstance(description, str), "Description must be text.")
    require(errors, isinstance(controls, list) and len(controls) > 0, "At least one risk control is required.")
    if isinstance(controls, list):
        errors.extend(validate_risk_analysis_rows(controls, risk_id or "newRiskAnalysis"))
    return errors, risk_id, controls if isinstance(controls, list) else []


def build_registry_entry(payload: dict[str, Any], risk_id: str) -> dict[str, Any]:
    return {
        "id": risk_id,
        "title": str(payload.get("title") or "").strip(),
        "description": str(payload.get("description") or ""),
        "path": f"riskTables/{risk_id}.json",
        "link": f"index.html?page=risk&service={risk_id}",
        "intro": [],
        "items": []
    }


@app.get("/api/editor/risk-tables")
def get_risk_tables_registry():
    try:
        registry = load_risk_registry()
        errors = validate_risk_registry(registry)
        if errors:
            return jsonify({"errors": errors}), 500
        return jsonify(registry)
    except (OSError, json.JSONDecodeError) as error:
        return jsonify({"error": str(error)}), 500


@app.get("/api/editor/risk-tables/<risk_id>")
def get_risk_table(risk_id: str):
    errors = validate_risk_id(risk_id)
    if errors:
        return jsonify({"errors": errors}), 400
    try:
        registry = load_risk_registry()
        if not find_risk_analysis_entry(registry, risk_id):
            return jsonify({"errors": [f"Unknown Risk Analysis: {risk_id}"]}), 404
        return jsonify(read_json(risk_table_path(risk_id)))
    except ValueError as error:
        return jsonify({"errors": [str(error)]}), 400
    except FileNotFoundError:
        return jsonify({"errors": [f"Risk Analysis file not found: {risk_id}"]}), 404
    except (OSError, json.JSONDecodeError) as error:
        return jsonify({"error": str(error)}), 500


@app.post("/api/editor/risk-tables/<risk_id>")
def save_risk_table(risk_id: str):
    errors = validate_risk_id(risk_id)
    if errors:
        return jsonify({"errors": errors}), 400
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or "data" not in payload:
        return jsonify({"errors": ["Request body must be JSON with a data field."]}), 400
    rows = payload["data"]
    row_errors = validate_risk_analysis_rows(rows, risk_id)
    if row_errors:
        return jsonify({"errors": row_errors}), 400
    try:
        registry = load_risk_registry()
        if not find_risk_analysis_entry(registry, risk_id):
            return jsonify({"errors": [f"Unknown Risk Analysis: {risk_id}"]}), 404
        path = risk_table_path(risk_id)
        atomic_write_json(path, rows)
        return jsonify({"ok": True, "serviceId": risk_id, "path": path.relative_to(DATA_DIR).as_posix()})
    except ValueError as error:
        return jsonify({"errors": [str(error)]}), 400
    except (OSError, json.JSONDecodeError) as error:
        app.logger.exception("Could not save Risk Analysis %s", risk_id)
        return jsonify({"errors": [f"Could not save Risk Analysis {risk_id}: {error}"]}), 500


@app.post("/api/editor/risk-tables")
def create_risk_table():
    payload = request.get_json(silent=True)
    try:
        registry = load_risk_registry()
        errors = validate_risk_registry(registry)
        if errors:
            return jsonify({"errors": errors}), 500
        errors, risk_id, controls = validate_create_risk_payload(payload, registry)
        if errors:
            return jsonify({"errors": errors}), 400
        path = risk_table_path(risk_id)
        if path.exists():
            return jsonify({"errors": [f"Risk Analysis file already exists: {risk_id}"]}), 400
        category_id = str(payload.get("categoryId") or "").strip()
        next_registry = json.loads(json.dumps(registry))
        category = find_risk_category_entry(next_registry, category_id)
        category["analyses"].append(build_registry_entry(payload, risk_id))
        atomic_write_json(path, controls)
        registry_errors = validate_risk_registry(next_registry)
        if registry_errors:
            path.unlink()
            return jsonify({"errors": registry_errors}), 400
        try:
            atomic_write_json(RISK_TABLE_REGISTRY_PATH, next_registry)
        except Exception:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise
        return jsonify({"ok": True, "serviceId": risk_id, "path": path.relative_to(DATA_DIR).as_posix()})
    except ValueError as error:
        return jsonify({"errors": [str(error)]}), 400
    except (OSError, json.JSONDecodeError) as error:
        app.logger.exception("Could not create Risk Analysis")
        return jsonify({"errors": [f"Could not create Risk Analysis: {error}"]}), 500


@app.get("/editor")
@app.get("/editor/")
def editor_index():
    return send_from_directory(EDITOR_DIR, "index.html")


@app.get("/editor/<path:filename>")
def editor_assets(filename: str):
    return send_from_directory(EDITOR_DIR, filename)


@app.get("/")
def public_index():
    return send_from_directory(PUBLIC_DIR, "index.html")


@app.get("/public")
@app.get("/public/")
def public_subdir_index():
    return send_from_directory(PUBLIC_DIR, "index.html")


@app.get("/public/<path:filename>")
def public_subdir_assets(filename: str):
    return send_from_directory(PUBLIC_DIR, filename)


@app.get("/<path:filename>")
def public_assets(filename: str):
    return send_from_directory(PUBLIC_DIR, filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)

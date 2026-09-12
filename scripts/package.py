"""Build and package a native release with its shell completions."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--target", help="Rust target supported by the build host")
parser.add_argument(
    "--output", type=Path, help="Archive directory; defaults to target/dist"
)
args = parser.parse_args()

metadata = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"], text=True
    )
)
root = Path(metadata["workspace_root"])
package = next(
    item
    for item in metadata["packages"]
    if Path(item["manifest_path"]) == root / "Cargo.toml"
)
version = package["version"]
if os.environ.get("GITHUB_REF_TYPE") == "tag":
    tag = os.environ["GITHUB_REF_NAME"]
    if tag != f"v{version}":
        raise ValueError(f"Release tag {tag} does not match Cargo version {version}")

compiler = subprocess.check_output(["rustc", "--version", "--verbose"], text=True)
host = next(
    line.removeprefix("host: ")
    for line in compiler.splitlines()
    if line.startswith("host: ")
)
target = args.target or host
command = ["cargo", "build", "--release", "--locked"]
build = Path(metadata["target_directory"])
if args.target:
    command += ["--target", target]
    build /= target
subprocess.run(command, check=True)

windows = "windows" in target
executable = "otunnel.exe" if windows else "otunnel"
binary = build / "release" / executable
name = f"otunnel-{target}-v{version}"
output = args.output or Path(metadata["target_directory"]) / "dist"
output = output.resolve()
output.mkdir(parents=True, exist_ok=True)

with tempfile.TemporaryDirectory(prefix="otunnel-package-") as temporary:
    directory = Path(temporary) / name
    directory.mkdir()
    shutil.copy2(binary, directory / executable)
    shutil.copy2(root / "README.md", directory / "README.md")
    shutil.copy2(root / "LICENSE", directory / "LICENSE")
    (directory / "docs").mkdir()
    shutil.copy2(root / "docs/configuration.md", directory / "docs/configuration.md")
    (directory / "examples").mkdir()
    shutil.copy2(root / "examples/embedded.rs", directory / "examples/embedded.rs")
    completions = directory / "completions"
    completions.mkdir()
    for shell, filename in (
        ("bash", "otunnel.bash"),
        ("elvish", "otunnel.elv"),
        ("fish", "otunnel.fish"),
        ("powershell", "otunnel.ps1"),
        ("zsh", "_otunnel"),
    ):
        with (completions / filename).open("wb") as stream:
            subprocess.run(
                [str(binary), "completion", shell], stdout=stream, check=True
            )
    archive = shutil.make_archive(
        str(output / name), "zip" if windows else "gztar", temporary, name
    )
print(archive)

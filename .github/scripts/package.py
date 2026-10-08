"""Archive each supported application and write its SHA-256 checksum."""

import argparse
import hashlib
from pathlib import Path
import tarfile
import zipfile


def package(target: str) -> None:
    windows = "-windows-" in target
    applications = ["cyclar-server"]
    if "-linux-" in target:
        applications.extend(["cyclar-host", "cyclar-desktop"])

    build_dir = Path("target") / target / "release"
    binaries = [build_dir / (app + (".exe" if windows else "")) for app in applications]
    license_path = Path("LICENSE")
    for source in [*binaries, license_path]:
        if not source.is_file():
            raise FileNotFoundError(f"Required package file is missing: {source}")

    output_dir = Path("artifacts")
    output_dir.mkdir(exist_ok=True)
    extension = ".zip" if windows else ".tar.gz"
    for app, binary in zip(applications, binaries):
        archive = output_dir / f"{app}-{target}{extension}"
        if windows:
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                bundle.write(binary, arcname=binary.name)
                bundle.write(license_path, arcname="LICENSE")
        else:
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(binary, arcname=binary.name)
                bundle.add(license_path, arcname="LICENSE")

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksum = archive.with_name(archive.name + ".sha256")
        checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
        print(archive)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Rust target triple used for the build")
    package(parser.parse_args().target)

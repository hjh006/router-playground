#!/usr/bin/env python3
"""Build the Android APK from an installed SDK/JDK, without Gradle or downloads."""
import argparse
import hashlib
import os
from pathlib import Path
import platform as host_platform
import re
import secrets
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent
BUILD = ROOT / "build"


def run(arguments, *, env=None):
    subprocess.run([str(value) for value in arguments], check=True, env=env)


def inside(path, directory):
    return path == directory or directory in path.parents


def find_java():
    if os.environ.get("JAVA_HOME"):
        java = Path(os.environ["JAVA_HOME"]).expanduser().resolve()
    elif host_platform.system() == "Darwin" and Path("/usr/libexec/java_home").exists():
        java = Path(subprocess.check_output(["/usr/libexec/java_home"], text=True).strip()).resolve()
    else:
        executable = shutil.which("javac")
        if not executable:
            raise SystemExit("Install a JDK and set JAVA_HOME or add javac to PATH.")
        java = Path(executable).resolve().parent.parent
    if not (java / "bin/javac").is_file() or not (java / "bin/java").is_file():
        raise SystemExit("JAVA_HOME must point to a complete JDK.")
    return java


def find_sdk(explicit):
    configured = explicit or os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if configured:
        return Path(configured).expanduser().resolve()
    relative = "Library/Android/sdk" if host_platform.system() == "Darwin" else "Android/Sdk"
    return (Path.home() / relative).resolve()


def reset_build_directory(directory):
    # Delete only a named cache below this module's real build directory.
    if BUILD.is_symlink() or directory.is_symlink() or not inside(directory.resolve(), BUILD.resolve()):
        raise SystemExit("Build cache must be a regular directory inside android/build.")
    if not inside(BUILD.resolve(), ROOT) or directory.resolve() == BUILD.resolve():
        raise SystemExit("Refusing to clean a directory outside the module build cache.")
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)


def default_signing_directory():
    if host_platform.system() == "Darwin":
        return Path.home() / "Library/Application Support/RouterControl/signing"
    data = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))).expanduser()
    return data / "router-control/signing"


def signing_identity(java, directory):
    directory = directory.expanduser().resolve()
    if inside(directory, REPOSITORY) or inside(REPOSITORY, directory):
        raise SystemExit("Signing directory must be outside the checkout and must not contain it.")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    password = directory / "signing-password"
    keystore = directory / "router-control.p12"
    if password.is_symlink() or keystore.is_symlink():
        raise SystemExit("Signing files must not be symbolic links.")
    if any(path.exists() and not path.is_file() for path in (password, keystore)):
        raise SystemExit("Signing identity entries must be regular files.")
    if keystore.exists() and not password.is_file():
        raise SystemExit("Signing password is missing; restore the original signing identity.")
    if not password.exists():
        descriptor = os.open(password, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as output:
            output.write(secrets.token_urlsafe(36) + "\n")
    password.chmod(0o600)
    if not keystore.exists():
        run([java / "bin/keytool", "-genkeypair", "-keystore", keystore,
             "-storetype", "PKCS12", "-alias", "router-control", "-keyalg", "RSA",
             "-keysize", "3072", "-validity", "10000", "-dname", "CN=Personal Router Control",
             "-storepass:file", password, "-keypass:file", password, "-noprompt"])
    keystore.chmod(0o600)
    return keystore, password


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, help="Android SDK directory")
    parser.add_argument("--platform", default="android-36.1", help="Installed SDK platform name")
    parser.add_argument("--build-tools", default="36.1.0", help="Installed build-tools version")
    parser.add_argument("--signing-dir", type=Path, help="External signing directory; keep it for later updates")
    parser.add_argument("--output", type=Path, help="APK output, default: build/router-control-<version>.apk")
    options = parser.parse_args()
    if host_platform.system() not in ("Darwin", "Linux"):
        raise SystemExit("This build entry supports macOS and Linux.")
    sdk = find_sdk(options.sdk)
    java = find_java()
    platform = sdk / "platforms" / options.platform / "android.jar"
    tools = sdk / "build-tools" / options.build_tools
    for required in [platform, tools / "aapt2", tools / "d8", tools / "zipalign", tools / "apksigner", java / "bin/keytool"]:
        if not required.is_file():
            raise SystemExit("Required SDK/JDK tool missing: " + str(required))
    manifest = ROOT / "AndroidManifest.xml"
    version = ET.parse(manifest).getroot().get("{http://schemas.android.com/apk/res/android}versionName", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", version):
        raise SystemExit("Manifest versionName must be a filename-safe version.")
    output = (options.output or BUILD / ("router-control-" + version + ".apk")).expanduser().resolve()
    signing = (options.signing_dir or Path(os.environ.get("ROUTER_ANDROID_SIGNING_DIR", str(default_signing_directory())))).expanduser().resolve()
    if inside(signing, REPOSITORY) or inside(REPOSITORY, signing):
        raise SystemExit("Signing directory must be outside the checkout and must not contain it.")
    if inside(output, signing):
        raise SystemExit("APK output must not overwrite files in the signing directory.")
    cache = BUILD / "apk"
    if inside(output, cache.resolve()):
        raise SystemExit("APK output must be outside the disposable build/apk cache.")
    sources = sorted((ROOT / "src").rglob("*.java"))
    if not sources:
        raise SystemExit("No Java sources in src/.")
    reset_build_directory(cache)
    generated, classes, dex = [cache / name for name in ("generated", "classes", "dex")]
    for folder in (generated, classes, dex):
        folder.mkdir()
    env = os.environ.copy()
    env["JAVA_HOME"] = str(java)
    run([tools / "aapt2", "compile", "--dir", ROOT / "res", "-o", cache / "resources.zip"])
    run([tools / "aapt2", "link", "-I", platform, "--manifest", manifest,
         "--java", generated, "-o", cache / "resources.apk", cache / "resources.zip"])
    run([java / "bin/javac", "--release", "8", "-encoding", "UTF-8", "-classpath", platform,
         "-d", classes, *sources, *sorted(generated.rglob("*.java"))])
    compiled = cache / "classes.jar"
    with zipfile.ZipFile(compiled, "w", zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(classes.rglob("*.class")):
            archive.write(source, source.relative_to(classes).as_posix())
    run([tools / "d8", "--release", "--min-api", "26", "--lib", platform,
         "--output", dex, compiled], env=env)
    packaged = cache / "packaged.apk"
    shutil.copyfile(cache / "resources.apk", packaged)
    with zipfile.ZipFile(packaged, "a", zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(dex.glob("*.dex")):
            archive.write(source, source.name)
    aligned = cache / "aligned.apk"
    run([tools / "zipalign", "-f", "4", packaged, aligned])
    keystore, password = signing_identity(java, signing)
    output.parent.mkdir(parents=True, exist_ok=True)
    run([tools / "apksigner", "sign", "--ks", keystore, "--ks-key-alias", "router-control",
         "--ks-pass", "file:" + str(password), "--out", output, aligned], env=env)
    run([tools / "apksigner", "verify", "--verbose", output], env=env)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + ".sha256").write_text(digest + "  " + output.name + "\n")
    print("APK: " + str(output))
    print("SHA-256: " + digest)


if __name__ == "__main__":
    main()

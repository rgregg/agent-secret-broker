#!/usr/bin/env python3
"""Render the Homebrew formula for `asb` from the release archives' .sha256 files.

usage: render_homebrew_formula.py TAG DIST_DIR > asb.rb

DIST_DIR holds asb-<platform>.tar.gz.sha256 for linux-amd64, linux-arm64, macos-arm64 and macos-amd64 (what the
cli-binaries CI job produces). The formula goes in a tap repository (rgregg/homebrew-tap, Formula/asb.rb).
"""
import pathlib
import sys

REPO = "rgregg/agent-secret-broker"
PLATFORMS = ("macos-arm64", "macos-amd64", "linux-arm64", "linux-amd64")


def sha(dist: pathlib.Path, platform: str) -> str:
    text = (dist / f"asb-{platform}.tar.gz.sha256").read_text().split()
    if not text or len(text[0]) != 64:
        raise SystemExit(f"bad checksum file for {platform}")
    return text[0]


def render(tag: str, dist: pathlib.Path) -> str:
    version = tag.removeprefix("v")
    url = lambda p: f"https://github.com/{REPO}/releases/download/{tag}/asb-{p}.tar.gz"

    def block(p: str) -> str:
        return f'      url "{url(p)}"\n      sha256 "{sha(dist, p)}"\n'

    return f'''class Asb < Formula
  desc "Command line for the agent secret broker: use credentials without ever seeing them"
  homepage "https://github.com/{REPO}"
  version "{version}"
  license "MIT"

  on_macos do
    on_arm do
{block("macos-arm64")}    end
    on_intel do
{block("macos-amd64")}    end
  end

  on_linux do
    on_arm do
{block("linux-arm64")}    end
    on_intel do
{block("linux-amd64")}    end
  end

  def install
    bin.install "asb"
  end

  test do
    assert_match "ask the broker for a secret", shell_output("#{{bin}}/asb help 2>&1")
  end
end
'''


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    sys.stdout.write(render(sys.argv[1], pathlib.Path(sys.argv[2])))

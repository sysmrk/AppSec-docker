#!/bin/sh
# Run INSIDE a disposable Trixie container, never on the host.
# No source execution, package download/installation or build.
set -eu
export LC_ALL=C
[ "$#" -eq 2 ] || { echo "Usage: SOURCE VERSION" >&2; exit 2; }
source=$1
version=$2
printf '%s\n' "$source" | grep -Eq '^[a-z0-9][a-z0-9+.-]*$'
printf '%s\n' "$version" | grep -Eq '^[0-9][a-zA-Z0-9.+:~-]*$'
. /etc/os-release
test "$ID" = debian
test "$VERSION_CODENAME" = trixie
key=/usr/share/keyrings/debian-archive-keyring.gpg
test -f "$key" || key=/usr/share/keyrings/debian-archive-keyring.pgp
test -f "$key"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
mkdir "$work/empty" "$work/lists" "$work/cache"
cat > "$work/sources.list" <<EOF
deb [signed-by=$key] https://mirrors.tuna.tsinghua.edu.cn/debian/ trixie main
deb [signed-by=$key] https://mirrors.tuna.tsinghua.edu.cn/debian/ trixie-updates main
deb [signed-by=$key] https://mirrors.tuna.tsinghua.edu.cn/debian-security/ trixie-security main
deb [signed-by=$key] https://mirrors.tuna.tsinghua.edu.cn/debian/ trixie-backports main
deb-src [signed-by=$key] https://mirrors.tuna.tsinghua.edu.cn/debian/ forky main
EOF
apt_local() {
    executable=$1
    shift
    command "$executable" \
      -o Dir::Etc::sourcelist="$work/sources.list" \
      -o Dir::Etc::sourceparts="$work/empty" \
      -o Dir::State::lists="$work/lists" \
      -o Dir::Cache="$work/cache" \
      -o Acquire::Languages=none \
      -o Acquire::Retries=1 \
      -o Acquire::https::Timeout=30 \
      -o Acquire::https::AllowRedirect=false \
      -o APT::Update::Error-Mode=any \
      -o Acquire::Check-Valid-Until=true \
      -o Acquire::AllowInsecureRepositories=false \
      -o APT::Get::AllowUnauthenticated=false \
      "$@"
}
apt_local apt-get update
echo "===== EXACT SOURCE RECORD ====="
# Read only selected signed source metadata, not all versions.
apt_local apt-cache showsrc "$source" | awk -v want="$version" -v pkg="$source" '
BEGIN {RS=""; FS="\n"; found=0}
{
  name=""; ver=""
  for(i=1;i<=NF;i++) {
    if($i ~ /^Package: /) name=substr($i,10)
    if($i ~ /^Version: /) ver=substr($i,10)
  }
  if(name==pkg && ver==want) {print $0 "\n"; found=1}
}
END {if(!found) exit 1}'
echo "===== BUILD DEPENDENCY SIMULATION (TRIXIE BINARIES ONLY) ====="
# Exact source version; forky has deb-src only. No installation or removal.
apt_local apt-get -s --no-remove --only-source build-dep "$source=$version"
echo "===== PREFLIGHT COMPLETE: simulation only ====="

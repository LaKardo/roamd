#!/bin/sh
set -u

RELEASE="${RELEASE:-25.12}"
JOBS="${JOBS:-$(nproc)}"

ROOT=$(cd "$(dirname "$0")" && pwd)
BUILD="$ROOT/build"
DIST="$ROOT/dist"
CACHE="$BUILD/feeds-cache-$RELEASE"

PACKAGES="roamd luci-app-roamd luci-i18n-roamd-ru"

case "$RELEASE" in
	*.*.*) ;;
	*)
		RELEASE=$(awk -v b="$RELEASE" '$1 == b { print $2 }' "$ROOT/targets/branches.txt" 2>/dev/null)
		[ -n "$RELEASE" ] || { echo "неизвестная ветка, см. targets/branches.txt" >&2; exit 1; }
		;;
esac

BRANCH="${RELEASE%.*}"
TARGET_MAP="$ROOT/targets/$BRANCH.txt"

TARGETS=$(sed 's#^\([^ ]*\) \(.*\)/\(.*\)$#\1:\2:\3#' "$TARGET_MAP" 2>/dev/null)

usage() {
	cat <<EOF
Сборка пакетов roamd для нескольких архитектур OpenWrt.

  $0                 собрать все архитектуры
  $0 <арх> [<арх>…]  собрать только указанные
  $0 --list          показать список архитектур
  $0 --prepare [<арх>…]  только скачать SDK и feeds (наполнение кеша)

Переменные окружения:
  RELEASE   версия OpenWrt (сейчас $RELEASE)
  JOBS      параллельность сборки (сейчас $JOBS)

Результат складывается в dist/<ветка>/<архитектура>/ (ветка — из RELEASE).
Список архитектур берётся из targets/<ветка>.txt, версии SDK — из targets/branches.txt.
EOF
}

list_targets() {
	for entry in $TARGETS; do
		arch=${entry%%:*}
		rest=${entry#*:}
		printf '  %-20s %s/%s\n' "$arch" "${rest%%:*}" "${rest#*:}"
	done
}

known_arch() {
	for entry in $TARGETS; do
		[ "${entry%%:*}" = "$1" ] && return 0
	done
	return 1
}

SDK_MIRRORS="${SDK_MIRRORS:-https://mirror-03.infra.openwrt.org https://downloads.openwrt.org https://archive.openwrt.org https://mirrors.tuna.tsinghua.edu.cn/openwrt}"
SDK_CACHE="${SDK_CACHE:-$BUILD/sdk-dl}"
START=$(date +%s)

# every line starts with the time since start, so a silent stage is visible as such
log() {
	t=$(( $(date +%s) - START ))
	printf '[%02d:%02d] %s\n' $((t / 60)) $((t % 60)) "$*"
}

mb() {
	echo "$(( $1 / 1048576 ))"
}

# one mirror: give up when it stays below 1 MB/s for 30 s, the next one may be faster
download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 2 --connect-timeout 15 ${3:+--speed-limit 1048576 --speed-time 30} -C - -o "$2" "$1"
	else
		wget -c -q --tries=2 --timeout=30 -O "$2" "$1"
	fi
}

range() {
	curl -fsSL --retry 3 --connect-timeout 15 -r "$3-$4" -o "$2" "$1"
}

remote_size() {
	curl -fsIL --connect-timeout 15 "$1" |
		tr -d '\r' | awk 'tolower($1) == "content-length:" { s = $2 } END { print s }'
}

# a mirror gives each connection a few hundred KB/s, so the SDK comes in SDK_SPLIT parts at once;
# wget fails on a Range header that does not start at 0, so this needs curl
download_split() {
	command -v curl >/dev/null 2>&1 || return 1
	n=${SDK_SPLIT:-8}
	size=$(remote_size "$1")
	case "$size" in ''|*[!0-9]*|0) return 1 ;; esac

	part=$(( (size + n - 1) / n ))
	pids=""
	i=0
	while [ "$i" -lt "$n" ]; do
		from=$((i * part))
		to=$((from + part - 1))
		[ "$to" -ge "$size" ] && to=$((size - 1))
		range "$1" "$2.part$i" "$from" "$to" &
		pids="$pids $!"
		i=$((i + 1))
	done

	ok=1
	last=0
	t0=$(date +%s)
	while :; do
		alive=0
		for pid in $pids; do
			kill -0 "$pid" 2>/dev/null && alive=1
		done
		[ "$alive" = 1 ] || break
		sleep 1
		now=$(date +%s)
		[ $((now - last)) -ge 10 ] || continue
		last=$now
		got=0
		for f in "$2".part*; do
			[ -f "$f" ] && got=$((got + $(wc -c < "$f")))
		done
		log "  скачано $(mb "$got") из $(mb "$size") МБ, $(( got / 1024 / (now - t0 + 1) )) КБ/с"
	done
	for pid in $pids; do
		wait "$pid" || ok=0
	done

	i=0
	: > "$2"
	while [ "$i" -lt "$n" ]; do
		[ "$ok" = 1 ] && cat "$2.part$i" >> "$2"
		rm -f "$2.part$i"
		i=$((i + 1))
	done

	[ "$ok" = 1 ] && [ "$(wc -c < "$2")" -eq "$size" ]
}

fetch_text() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 15 --max-time 60 "$1"
	else
		wget -qO- --timeout=30 "$1"
	fi
}

fetch_sdk() {
	target=$1
	subtarget=$2
	dir=$3
	path="releases/$RELEASE/targets/$target/$subtarget"

	[ -d "$dir" ] && return 0

	sums=""
	for m in $SDK_MIRRORS; do
		sums=$(fetch_text "$m/$path/sha256sums" 2>/dev/null) && [ -n "$sums" ] && break
	done
	line=$(printf '%s\n' "$sums" | grep -E '\*?openwrt-sdk-[^ ]*\.tar\.(zst|xz)$' | head -1)
	sha=${line%% *}
	name=${line##*[ *]}
	if [ -z "$line" ] || [ -z "$name" ]; then
		echo "  SDK не найден: $target/$subtarget ($RELEASE)" >&2
		return 1
	fi

	mkdir -p "$SDK_CACHE"
	file="$SDK_CACHE/$name"

	if [ -f "$file" ] && echo "$sha  $file" | sha256sum -c - >/dev/null 2>&1; then
		log "SDK из кеша: $name"
	else
		ok=0
		first=""
		for m in $SDK_MIRRORS; do
			first=${first:-$m}
			log "Скачивание SDK $name ($m, ${SDK_SPLIT:-8} соединений)"
			if download_split "$m/$path/$name" "$file" ||
			   { rm -f "$file"; log "  по частям нельзя (нет curl или размера), обычная загрузка"; download "$m/$path/$name" "$file" fast; }; then
				echo "$sha  $file" | sha256sum -c - >/dev/null 2>&1 && { ok=1; break; }
				rm -f "$file"
			fi
			log "  $m: не удалось или медленно, следующее зеркало" >&2
		done
		if [ "$ok" != 1 ]; then
			log "  все зеркала медленные, докачка с $first без ограничения скорости"
			download "$first/$path/$name" "$file" &&
				echo "$sha  $file" | sha256sum -c - >/dev/null 2>&1 && ok=1
		fi
		if [ "$ok" != 1 ]; then
			rm -f "$file"
			log "  SDK не скачан или не совпала контрольная сумма" >&2
			return 1
		fi
		log "SDK скачан, контрольная сумма совпала"
		find "$SDK_CACHE" -name 'openwrt-sdk-*' ! -name "$name" -delete 2>/dev/null
	fi

	log "Распаковка SDK"
	mkdir -p "$dir"
	case "$name" in
	*.zst) tar --zstd -xf "$file" -C "$dir" --strip-components=1 ;;
	*.xz)  tar -xJf "$file" -C "$dir" --strip-components=1 ;;
	esac || { rm -rf "$dir"; return 1; }
}

prepare_feeds() {
	dir=$1

	if ! grep -q ' luci ' "$dir/feeds.conf" 2>/dev/null; then
		for feed in base luci; do
			awk -v want="$feed" '/^src-git/ {
				for (i = 2; i <= NF; i++)
					if ($i == want) { print; break }
			}' "$dir/feeds.conf.default"
		done > "$dir/feeds.conf"
	fi

	mkdir -p "$dir/feeds"

	if [ -d "$CACHE/base" ]; then
		for entry in "$CACHE"/*; do
			name=$(basename "$entry")
			[ -e "$dir/feeds/$name" ] || cp -al "$entry" "$dir/feeds/$name"
		done
	fi

	if [ ! -d "$dir/package/feeds/luci/luci-base" ] || [ ! -d "$dir/package/feeds/base/uclient" ]; then
		log "Feeds base и luci: git clone/update (без вывода, обычно несколько минут)"
		( cd "$dir" && ./scripts/feeds update base luci >/dev/null 2>&1 )
		( cd "$dir" && ./scripts/feeds install -a -p luci >/dev/null 2>&1 )
		( cd "$dir" && ./scripts/feeds install -p base libubox libubus libuci ucode uclient ustream-ssl >/dev/null 2>&1 )
	else
		log "Feeds base и luci уже на месте"
	fi

	for name in base luci; do
		if [ ! -d "$dir/feeds/$name" ] || [ ! -f "$dir/feeds/$name.index" ]; then
			log "  feed $name не подготовлен" >&2
			return 1
		fi
	done

	if [ ! -d "$CACHE/base" ]; then
		mkdir -p "$CACHE"
		for name in base base.index base.targetindex luci luci.index luci.targetindex; do
			[ -e "$dir/feeds/$name" ] && cp -al "$dir/feeds/$name" "$CACHE/$name"
		done
	fi
}

build_arch() {
	arch=$1
	target=$2
	subtarget=$3
	dir="$BUILD/sdk-$RELEASE-$target-$subtarget"

	fetch_sdk "$target" "$subtarget" "$dir" || return 1
	prepare_feeds "$dir" || { echo "  не удалось подготовить feeds" >&2; return 1; }
	[ "$PREPARE_ONLY" = 1 ] && return 0

	ln -sfn "$ROOT/package/roamd" "$dir/package/roamd"
	ln -sfn "$ROOT/package/luci-app-roamd" "$dir/package/luci-app-roamd"

	rm -rf "$dir/tmp"
	log "Настройка SDK (make defconfig)"
	( cd "$dir" && make defconfig >/dev/null 2>&1 ) || return 1

	# the SDK selects every package by default, which builds openssl and wolfssl for nothing:
	# drop that and every module it marked, keep only ours and the Russian translation
	sed -i -E -e 's/^(CONFIG_ALL(_NONSHARED|_KMODS)?)=y$/# \1 is not set/' \
		-e '/^CONFIG_PACKAGE_[^=]*=m$/d' -e '/^# CONFIG_LUCI_LANG_ru is not set$/d' "$dir/.config"
	echo "CONFIG_LUCI_LANG_ru=y" >> "$dir/.config"

	for pkg in $PACKAGES; do
		grep -q "^CONFIG_PACKAGE_$pkg=m" "$dir/.config" ||
			echo "CONFIG_PACKAGE_$pkg=m" >> "$dir/.config"
	done

	( cd "$dir" && make defconfig >/dev/null 2>&1 ) || return 1

	real=$(grep -m1 '^CONFIG_TARGET_ARCH_PACKAGES=' "$dir/.config" | cut -d'"' -f2)
	if [ -z "$real" ]; then
		echo "  SDK не сообщил архитектуру пакетов" >&2
		return 1
	fi
	if [ "$real" != "$arch" ]; then
		echo "  внимание: SDK даёт $real, в таблице указано $arch" >&2
	fi

	find "$dir/bin/packages" \( -name 'roamd[-_]*' -o -name 'luci-app-roamd[-_]*' \
		-o -name 'luci-i18n-roamd-ru[-_]*' \) -delete 2>/dev/null

	log "Сборка: зависимости (libubox, ubus, uci, uclient…), затем roamd и luci-app-roamd"
	( cd "$dir" && make package/roamd/compile package/luci-app-roamd/compile -j"$JOBS" >"$dir/build.log" 2>&1 ) &
	mpid=$!
	shown=""
	while kill -0 "$mpid" 2>/dev/null; do
		sleep 2
		# "make[2] -C feeds/base/package/libs/libubox compile" -> libubox
		cur=$(sed -n 's#.* -C \([^ ]*\) \(compile\|host/compile\).*#\1 \2#p' "$dir/build.log" 2>/dev/null |
			tail -1 | sed 's#^.*/\([^/ ]*\) #\1 #; s# compile$##; s# host/compile$# (для хоста)#')
		[ -n "$cur" ] && [ "$cur" != "$shown" ] && { log "  собирается $cur"; shown=$cur; }
		# the SDK fetches package sources itself and says nothing while it does
		dl=$(ls "$dir/dl"/*.dl 2>/dev/null | head -1)
		[ -n "$dl" ] && [ "$dl" != "${dlshown-}" ] && { log "  скачивание исходников $(basename "$dl" .dl)"; dlshown=$dl; }
	done
	wait "$mpid" || {
		log "  сборка не удалась, журнал: $dir/build.log" >&2
		tail -n 20 "$dir/build.log" >&2
		return 1
	}
	log "Сборка завершена"

	out="$DIST/${RELEASE%.*}/$real"
	mkdir -p "$out"
	rm -f "$out"/*.ipk "$out"/*.apk

	found=0
	for pattern in 'roamd_*.ipk' 'luci-app-roamd_*.ipk' 'luci-i18n-roamd-*.ipk' \
		       'roamd-[0-9]*.apk' 'luci-app-roamd-[0-9]*.apk' 'luci-i18n-roamd-ru-[0-9]*.apk'; do
		for file in $(find "$dir/bin/packages" -name "$pattern" 2>/dev/null); do
			cp "$file" "$out/"
			found=$((found + 1))
		done
	done

	if [ "$found" -lt 3 ]; then
		echo "  собрано пакетов: $found из 3" >&2
		return 1
	fi

	ls "$out" | grep -E '\.(ipk|apk)$' | while read -r name; do
		echo "  dist/${RELEASE%.*}/$real/$name"
	done
}

PREPARE_ONLY=0

case "${1-}" in
--prepare)
	PREPARE_ONLY=1
	shift
	;;
--list|-l)
	echo "Доступные архитектуры:"
	list_targets
	exit 0
	;;
--help|-h)
	usage
	exit 0
	;;
esac

for arg in "$@"; do
	if ! known_arch "$arg"; then
		echo "Неизвестная архитектура: $arg" >&2
		echo "Доступные:" >&2
		list_targets >&2
		exit 1
	fi
done

mkdir -p "$BUILD" "$DIST"

built=""
failed=""

for entry in $TARGETS; do
	arch=${entry%%:*}
	rest=${entry#*:}
	target=${rest%%:*}
	subtarget=${rest#*:}

	if [ $# -gt 0 ]; then
		wanted=0
		for arg in "$@"; do
			[ "$arg" = "$arch" ] && wanted=1
		done
		[ "$wanted" = 1 ] || continue
	fi

	log "==> $arch  ($target/$subtarget, SDK $RELEASE)"

	if build_arch "$arch" "$target" "$subtarget"; then
		built="$built $arch"
	else
		failed="$failed $arch"
	fi
done

echo
log "Собрано:${built:- —}"
[ -n "$failed" ] && log "Не собрано:$failed" >&2

[ -z "$failed" ]

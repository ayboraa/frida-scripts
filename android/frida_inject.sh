#!/bin/bash
# ============================================================
#  frida_inject.sh — XAPK/APK'ya Frida Gadget otomatik enjeksiyon
#  Kullanım: ./frida_inject.sh <dosya.xapk|dosya.apk> <libfrida-gadget.so> [keystore] [keystore_pass]
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; exit 1; }

[ "$#" -lt 2 ] && err "Kullanım: $0 <dosya.xapk|dosya.apk> <libfrida-gadget.so> [keystore] [keystore_pass]"

INPUT_FILE="$(realpath "$1")"
GADGET_SO="$(realpath "$2")"
KEYSTORE="${3:-}"
KS_PASS="${4:-android}"

[ ! -f "$INPUT_FILE" ] && err "Girdi dosyası bulunamadı: $INPUT_FILE"
[ ! -f "$GADGET_SO" ]  && err "Gadget .so bulunamadı: $GADGET_SO"

# Girdi tipini uzantıya göre belirle
case "${INPUT_FILE,,}" in
    *.xapk) IS_XAPK=true ;;
    *.apk)  IS_XAPK=false ;;
    *) err "Desteklenmeyen dosya uzantısı (.xapk veya .apk olmalı): $INPUT_FILE" ;;
esac

for tool in apktool zipalign apksigner aapt adb unzip zip keytool python3; do
    command -v "$tool" &>/dev/null || err "'$tool' bulunamadı."
done

WORKDIR="$(pwd)/frida_work_$(date +%s)"
mkdir -p "$WORKDIR"
log "Çalışma dizini: $WORKDIR"
if $IS_XAPK; then
    log "Girdi tipi: XAPK"
else
    log "Girdi tipi: APK (tekil paket, split yok)"
fi

# ============================================================
# ADIM 1 — Girdi dosyası hazırlanıyor
# ============================================================
log "ADIM 1: Girdi dosyası hazırlanıyor..."
XAPK_DIR="$WORKDIR/xapk"
mkdir -p "$XAPK_DIR"

if $IS_XAPK; then
    unzip -q "$INPUT_FILE" -d "$XAPK_DIR"

    BASE_APK=$(find "$XAPK_DIR" -maxdepth 1 -name "*.apk" ! -name "config.*" | sort | head -1)
    [ -z "$BASE_APK" ] && err "Base APK bulunamadı!"

    CONFIG_ARM64=$(find "$XAPK_DIR" -maxdepth 1 -name "config.arm64_v8a.apk" | head -1)
    [ -z "$CONFIG_ARM64" ] && warn "config.arm64_v8a.apk bulunamadı — gadget base APK'ya eklenecek"

    ok "ADIM 1: XAPK açıldı — Base: $(basename "$BASE_APK")"
else
    # Tekil APK: split/config APK yok, gadget doğrudan base APK'ya eklenecek
    BASE_APK="$XAPK_DIR/$(basename "$INPUT_FILE")"
    cp "$INPUT_FILE" "$BASE_APK"
    CONFIG_ARM64=""
    ok "ADIM 1: APK hazırlandı — $(basename "$BASE_APK")"
fi

# ============================================================
# ADIM 2 — Gadget config
# ============================================================
log "ADIM 2: Gadget config oluşturuluyor..."
GADGET_CONFIG="$WORKDIR/libfrida-gadget.config.so"
printf '{\n  "interaction": {\n    "type": "listen",\n    "address": "0.0.0.0",\n    "port": 27042,\n    "on_port_conflict": "fail",\n    "on_load": "wait"\n  }\n}\n' > "$GADGET_CONFIG"
ok "ADIM 2: Config oluşturuldu"

# ============================================================
# ADIM 3 — apktool decode
# ============================================================
log "ADIM 3: apktool decode..."
DECODE_DIR="$WORKDIR/decoded"
apktool d "$BASE_APK" -o "$DECODE_DIR" --no-res -f 2>&1 | grep -E "^I:|error" || true
[ ! -d "$DECODE_DIR/smali" ] && err "Decode başarısız!"
ok "ADIM 3: Decode tamamlandı"

# ============================================================
# ADIM 4 — Inject hedefi tespiti
#
# Öncelik:
#   1. MAIN+LAUNCHER olan enabled gerçek activity
#   2. MAIN+LAUNCHER olan enabled alias -> targetActivity
#   3. MAIN+LAUNCHER olan herhangi alias -> targetActivity
#   4. Adında "MainActivity" geçen herhangi activity
#   5. Smali ağacında MainActivity.smali
#   6. İlk enabled exported activity
# ============================================================
log "ADIM 4: Inject hedefi tespit ediliyor..."

MAIN_ACTIVITY=$(aapt dump xmltree "$BASE_APK" AndroidManifest.xml | python3 << 'PYEOF'
import sys, re

lines = sys.stdin.read().splitlines()
blocks = []
cur = None

for line in lines:
    s = line.strip()

    if re.match(r'E: activity\b', s):
        cur = {'type': 'activity', 'name': None, 'enabled': True,
               'target': None, 'has_main': False, 'has_launcher': False}
        blocks.append(cur)
        continue

    if re.match(r'E: activity-alias\b', s):
        cur = {'type': 'alias', 'name': None, 'enabled': True,
               'target': None, 'has_main': False, 'has_launcher': False}
        blocks.append(cur)
        continue

    if re.match(r'E: (service|receiver|provider|uses-permission|uses-feature|permission|meta-data|property)\b', s):
        cur = None
        continue

    if cur is None:
        continue

    if 'A: android:name' in s and cur['name'] is None:
        m = re.search(r'"([^"]+)"', s)
        if m: cur['name'] = m.group(1)

    if 'A: android:enabled' in s:
        cur['enabled'] = '0xffffffff' in s

    if 'A: android:targetActivity' in s:
        m = re.search(r'"([^"]+)"', s)
        if m: cur['target'] = m.group(1)

    if 'android.intent.action.MAIN' in s:      cur['has_main']     = True
    if 'android.intent.category.LAUNCHER' in s: cur['has_launcher'] = True

L = [b for b in blocks if b['has_main'] and b['has_launcher']]

# 1. enabled gerçek activity
for b in L:
    if b['type'] == 'activity' and b['enabled'] and b['name']:
        print(b['name']); sys.exit(0)

# 2. enabled alias -> target
for b in L:
    if b['type'] == 'alias' and b['enabled'] and b['target']:
        print(b['target']); sys.exit(0)

# 3. herhangi alias -> target
for b in L:
    if b['type'] == 'alias' and b['target']:
        print(b['target']); sys.exit(0)

# 4. adında MainActivity geçen
for b in blocks:
    if b['type'] == 'activity' and b['name'] and 'MainActivity' in b['name']:
        print(b['name']); sys.exit(0)

# 5. ilk enabled exported activity
for b in blocks:
    if b['type'] == 'activity' and b['enabled'] and b['name']:
        print(b['name']); sys.exit(0)

sys.exit(1)
PYEOF
) || true

# Manifest'ten bulunamadıysa smali'de ara
if [ -z "$MAIN_ACTIVITY" ]; then
    warn "Manifest'ten bulunamadı, smali'de MainActivity aranıyor..."
    SMALI_HIT=$(find "$DECODE_DIR"/smali* -name "MainActivity.smali" 2>/dev/null | head -1)
    if [ -n "$SMALI_HIT" ]; then
        MAIN_ACTIVITY=$(echo "$SMALI_HIT" | sed "s|.*/smali[^/]*/||;s|\.smali$||;s|/|.|g")
    fi
fi

[ -z "$MAIN_ACTIVITY" ] && err "Inject hedefi bulunamadı!"
ok "ADIM 4: Inject hedefi: $MAIN_ACTIVITY"

# ============================================================
# ADIM 5 — Smali enjeksiyonu
# ============================================================
log "ADIM 5: Smali enjeksiyonu..."

SMALI_REL=$(echo "$MAIN_ACTIVITY" | tr '.' '/').smali
SMALI_FILE=""
for d in "$DECODE_DIR"/smali*; do
    [ -f "$d/$SMALI_REL" ] && SMALI_FILE="$d/$SMALI_REL" && break
done
[ -z "$SMALI_FILE" ] && err "Smali bulunamadı: $SMALI_REL"
ok "Smali: $SMALI_FILE"

python3 << PYEOF
import re, sys

path = "$SMALI_FILE"
src  = open(path).read()

load_call = '    const-string v0, "frida-gadget"\n    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'

if 'frida-gadget' in src:
    print("[!] Zaten enjekte edilmiş, atlanıyor")
    sys.exit(0)

if '.method static constructor <clinit>' in src:
    def patch(m):
        block = m.group(0)
        loc = re.search(r'(\.locals )(\d+)', block)
        if loc:
            if int(loc.group(2)) < 1:
                block = block[:loc.start(2)] + '1' + block[loc.end(2):]
                loc = re.search(r'(\.locals )(\d+)', block)
            p = block.index('\n', loc.start()) + 1
            return block[:p] + load_call + block[p:]
        return block
    out = re.sub(r'\.method static constructor <clinit>\(\)V.*?\.end method',
                 patch, src, flags=re.DOTALL)
else:
    clinit = (
        "\n.method static constructor <clinit>()V\n"
        "    .locals 1\n\n"
        + load_call +
        "\n    return-void\n.end method\n\n"
    )
    m = re.search(r'^\.method ', src, re.MULTILINE)
    if not m: print("[-] .method bulunamadı"); sys.exit(1)
    out = src[:m.start()] + clinit + src[m.start():]

open(path, 'w').write(out)
print("[+] Smali enjeksiyonu tamam")
PYEOF

ok "ADIM 5: Smali enjeksiyonu tamamlandı"

# ============================================================
# ADIM 6 — apktool build
# ============================================================
log "ADIM 6: apktool build..."
BUILD_APK="$WORKDIR/built.apk"

if ! apktool b "$DECODE_DIR" -o "$BUILD_APK" --use-aapt2 2>&1 | tee /tmp/_apktool.log | grep -q "^I: Built"; then
    warn "--use-aapt2 başarısız, standart build deneniyor..."
    rm -f "$BUILD_APK"
    apktool b "$DECODE_DIR" -o "$BUILD_APK" 2>&1 | tail -5
fi
[ ! -f "$BUILD_APK" ] && err "Build başarısız!"
ok "ADIM 6: Build tamamlandı"

# ============================================================
# ADIM 7 — DEX aktar
# ============================================================
log "ADIM 7: DEX aktarılıyor..."
BASE_WORK="$WORKDIR/base_work.apk"
cp "$BASE_APK" "$BASE_WORK"

DEX_TMP="$WORKDIR/dex_tmp"
mkdir -p "$DEX_TMP"
unzip -q "$BUILD_APK" "classes*.dex" -d "$DEX_TMP" 2>/dev/null || true

DEX_COUNT=$(find "$DEX_TMP" -name "classes*.dex" | wc -l)
[ "$DEX_COUNT" -eq 0 ] && err "DEX üretilemedi!"

cd "$DEX_TMP" && zip -u "$BASE_WORK" classes*.dex && cd "$WORKDIR"
ok "ADIM 7: DEX aktarıldı ($DEX_COUNT adet)"

# ============================================================
# ADIM 8 — Gadget ekle (stored)
# ============================================================
log "ADIM 8: Gadget ekleniyor..."

if [ -n "${CONFIG_ARM64:-}" ]; then
    TARGET_LIB_APK="$CONFIG_ARM64"
    log "Hedef: config.arm64_v8a.apk"
else
    TARGET_LIB_APK="$BASE_WORK"
    log "Hedef: base APK"
fi

LIB_TMP="$WORKDIR/lib_tmp"
mkdir -p "$LIB_TMP/lib/arm64-v8a"
cp "$GADGET_SO"     "$LIB_TMP/lib/arm64-v8a/libfrida-gadget.so"
cp "$GADGET_CONFIG" "$LIB_TMP/lib/arm64-v8a/libfrida-gadget.config.so"

cd "$LIB_TMP"
zip -0 "$TARGET_LIB_APK" lib/arm64-v8a/libfrida-gadget.so lib/arm64-v8a/libfrida-gadget.config.so
cd "$WORKDIR"

unzip -v "$TARGET_LIB_APK" | grep "frida-gadget" | grep -q "Stored" || err "Gadget Stored değil!"
cp "$BASE_WORK" "$BASE_APK"
ok "ADIM 8: Gadget eklendi (Stored)"

# ============================================================
# ADIM 9 — Keystore
# ============================================================
log "ADIM 9: Keystore hazırlanıyor..."
if [ -n "$KEYSTORE" ] && [ -f "$KEYSTORE" ]; then
    KEYSTORE="$(realpath "$KEYSTORE")"
    ok "Mevcut keystore: $KEYSTORE"
else
    KEYSTORE="$WORKDIR/inject.keystore"
    warn "Yeni keystore oluşturuluyor..."
    keytool -genkey -v \
        -keystore "$KEYSTORE" -alias mykey \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Inject, OU=CTF, O=CTF, L=TR, ST=TR, C=TR" \
        -storepass "$KS_PASS" -keypass "$KS_PASS" > /dev/null 2>&1
    ok "Keystore oluşturuldu"
fi

# ============================================================
# ADIM 10 — Zipalign + imzala
# ============================================================
log "ADIM 10: Zipalign + imzalama..."
SIGNED_DIR="$WORKDIR/signed"
mkdir -p "$SIGNED_DIR"

for apk in "$XAPK_DIR"/*.apk; do
    fname=$(basename "$apk")
    aligned="$WORKDIR/aligned_${fname}"
    signed="$SIGNED_DIR/$fname"
    log "  → $fname"
    zipalign -f -p 4096 "$apk" "$aligned"
    apksigner sign \
        --ks "$KEYSTORE" \
        --ks-pass "pass:$KS_PASS" \
        --key-pass "pass:$KS_PASS" \
        --out "$signed" "$aligned"
    ok "    OK: $fname"
done
ok "ADIM 10: Tüm APK'lar imzalandı"

# ============================================================
# ADIM 11 — ADB install
# ============================================================
log "ADIM 11: ADB install..."
ADB_DEV=$(adb devices 2>/dev/null | grep -v "List of devices" | grep -c "device$") || ADB_DEV=0

SIGNED_APKS=("$SIGNED_DIR"/*.apk)
NUM_SIGNED=${#SIGNED_APKS[@]}

if [ "$ADB_DEV" -eq 0 ]; then
    warn "Cihaz bulunamadı. Manuel yükle:"
    echo ""
    echo "  cd \"$SIGNED_DIR\""
    if [ "$NUM_SIGNED" -gt 1 ]; then
        echo "  adb install-multiple --no-incremental *.apk"
    else
        echo "  adb install -r \"$(basename "${SIGNED_APKS[0]}")\""
    fi
    echo ""
else
    PKG=$(aapt dump badging "$BASE_APK" 2>/dev/null | grep "^package:" | grep -o "name='[^']*'" | cut -d"'" -f2) || PKG=""
    [ -n "$PKG" ] && { log "Kaldırılıyor: $PKG"; adb uninstall "$PKG" 2>/dev/null || true; }

    cd "$SIGNED_DIR"
    if [ "$NUM_SIGNED" -gt 1 ]; then
        adb install-multiple --no-incremental *.apk
    else
        adb install -r "$(basename "${SIGNED_APKS[0]}")"
    fi
    cd "$WORKDIR"
    ok "Yükleme başarılı!"

    adb forward tcp:27042 tcp:27042
    ok "Port forward: localhost:27042"
    echo ""
    log "Uygulamayı başlatın, ardından:"
    echo "  frida -U -n Gadget -l script.js"
    echo ""
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  TAMAMLANDI${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  İmzalı APK'lar : $SIGNED_DIR"
echo -e "  Keystore       : $KEYSTORE"
echo ""

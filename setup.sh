#!/usr/bin/env bash
# =============================================================================
# setup.sh — Instalador automático del PS5 Toolkit 11.xx
#
# Prepara el entorno del PC para servir el exploit y enviar payloads.
# Compatible con: Debian/Ubuntu, macOS, Arch Linux
#
# Uso:
#   chmod +x setup.sh
#   ./setup.sh
#   ./setup.sh --sdk    # Instala también el ps5-payload-sdk (para compilar C)
#   ./setup.sh --check  # Solo verifica dependencias sin instalar nada
# =============================================================================

set -euo pipefail

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;93m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

# ── Flags ─────────────────────────────────────────────────────────────────────
INSTALL_SDK=false
CHECK_ONLY=false

for arg in "$@"; do
    case $arg in
        --sdk)   INSTALL_SDK=true  ;;
        --check) CHECK_ONLY=true   ;;
        --help)
            echo "Uso: $0 [--sdk] [--check]"
            echo "  --sdk    Instala también el ps5-payload-sdk"
            echo "  --check  Solo verifica dependencias"
            exit 0
            ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────

ok()   { echo -e "  ${GRN}✓${RST}  $*"; }
warn() { echo -e "  ${YLW}⚠${RST}  $*"; }
err()  { echo -e "  ${RED}✗${RST}  $*"; }
info() { echo -e "  ${CYN}→${RST}  $*"; }
hdr()  { echo -e "\n${BLD}$*${RST}"; }

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/arch-release ]]; then
        echo "arch"
    else
        echo "unknown"
    fi
}

check_cmd() {
    local cmd=$1
    local name=${2:-$cmd}
    if command -v "$cmd" &>/dev/null; then
        ok "$name: $(command -v "$cmd")"
        return 0
    else
        err "$name: no encontrado"
        return 1
    fi
}

check_python_version() {
    if command -v python3 &>/dev/null; then
        local ver
        ver=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        local major minor
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [[ $major -ge 3 && $minor -ge 8 ]]; then
            ok "Python $ver (≥ 3.8 requerido)"
            return 0
        else
            err "Python $ver encontrado pero se necesita ≥ 3.8"
            return 1
        fi
    else
        err "Python 3 no encontrado"
        return 1
    fi
}

# ── Banner ────────────────────────────────────────────────────────────────────

echo -e "${BLD}${CYN}"
echo "  ██████╗ ███████╗███████╗    ████████╗ ██████╗  ██████╗ ██╗"
echo "  ██╔══██╗██╔════╝██╔════╝       ██╔══╝██╔═══██╗██╔═══██╗██║"
echo "  ██████╔╝███████╗███████╗       ██║   ██║   ██║██║   ██║██║"
echo "  ██╔═══╝ ╚════██║╚════██║       ██║   ██║   ██║██║   ██║██║"
echo "  ██║     ███████║███████║       ██║   ╚██████╔╝╚██████╔╝███████╗"
echo "  ╚═╝     ╚══════╝╚══════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝"
echo -e "${RST}"
echo -e "  ${BLD}PS5 Toolkit 11.xx — Setup Script${RST}"
echo -e "  FW 11.00 · ELF/BIN/SELF payload injector"
echo ""

OS=$(detect_os)
info "Sistema operativo detectado: $OS"

# ── Check de dependencias ─────────────────────────────────────────────────────

hdr "[ 1/4 ] Verificando dependencias"

MISSING=0

check_python_version  || MISSING=$((MISSING+1))
check_cmd nc   "netcat"   || warn "netcat opcional (alternativa a send_payload.py)"
check_cmd git  "git"      || MISSING=$((MISSING+1))

if $INSTALL_SDK; then
    check_cmd clang  "clang"   || MISSING=$((MISSING+1))
    check_cmd make   "make"    || MISSING=$((MISSING+1))
fi

if [[ $MISSING -gt 0 && "$CHECK_ONLY" == true ]]; then
    echo ""
    err "$MISSING dependencia(s) faltantes. Ejecuta './setup.sh' para instalarlas."
    exit 1
fi

if [[ "$CHECK_ONLY" == true ]]; then
    echo ""
    ok "Todas las dependencias están disponibles."
    exit 0
fi

# ── Instalación de dependencias ───────────────────────────────────────────────

if [[ $MISSING -gt 0 ]]; then
    hdr "[ 2/4 ] Instalando dependencias faltantes"

    case $OS in
        debian)
            info "Actualizando apt..."
            sudo apt-get update -qq
            sudo apt-get install -y python3 python3-pip git netcat-openbsd
            if $INSTALL_SDK; then
                sudo apt-get install -y clang make llvm
            fi
            ;;
        macos)
            if ! command -v brew &>/dev/null; then
                err "Homebrew no encontrado. Instálalo desde https://brew.sh"
                exit 1
            fi
            brew install python3 git netcat
            if $INSTALL_SDK; then
                brew install llvm make
            fi
            ;;
        arch)
            sudo pacman -Sy --noconfirm python python-pip git gnu-netcat
            if $INSTALL_SDK; then
                sudo pacman -Sy --noconfirm clang make llvm
            fi
            ;;
        *)
            warn "Sistema operativo no reconocido. Instala manualmente: python3, git, netcat"
            ;;
    esac
else
    hdr "[ 2/4 ] Dependencias ya instaladas"
    ok "Nada que instalar."
fi

# ── Configuración del proyecto ────────────────────────────────────────────────

hdr "[ 3/4 ] Configurando el proyecto"

# Crear carpetas necesarias
mkdir -p payloads
ok "Carpeta payloads/ creada"

# Detectar IP local
LOCAL_IP=""
if command -v ip &>/dev/null; then
    LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || true)
elif command -v ifconfig &>/dev/null; then
    LOCAL_IP=$(ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1 || true)
fi

if [[ -n "$LOCAL_IP" ]]; then
    ok "IP local detectada: $LOCAL_IP"

    # Parchear HOST_IP en loader.js automáticamente
    if [[ -f "exploit/js/loader.js" ]]; then
        if grep -q '192.168.1.100' exploit/js/loader.js; then
            sed -i.bak "s/192\.168\.1\.100/$LOCAL_IP/g" exploit/js/loader.js
            ok "HOST_IP actualizado en exploit/js/loader.js → $LOCAL_IP"
        else
            warn "HOST_IP ya fue configurado previamente en loader.js"
        fi
    fi

    # Parchear IP en el payload de ejemplo
    if [[ -f "payload/example/hello.c" ]]; then
        if grep -q '192.168.1.100' payload/example/hello.c; then
            sed -i.bak "s/192\.168\.1\.100/$LOCAL_IP/g" payload/example/hello.c
            ok "IP actualizada en payload/example/hello.c → $LOCAL_IP"
        fi
    fi
else
    warn "No se pudo detectar la IP local automáticamente."
    warn "Edita manualmente exploit/js/loader.js y cambia HOST_IP."
fi

# ── ps5-payload-sdk (opcional) ────────────────────────────────────────────────

if $INSTALL_SDK; then
    hdr "[ 4/4 ] Instalando ps5-payload-sdk"

    SDK_DIR="/opt/ps5-payload-sdk"

    if [[ -d "$SDK_DIR" ]]; then
        warn "ps5-payload-sdk ya existe en $SDK_DIR"
    else
        info "Clonando ps5-payload-sdk..."
        git clone --depth=1 https://github.com/ps5-payload-dev/sdk /tmp/ps5-payload-sdk-src

        info "Instalando en $SDK_DIR (requiere sudo)..."
        sudo mkdir -p "$SDK_DIR"
        sudo cp -r /tmp/ps5-payload-sdk-src/* "$SDK_DIR/"
        rm -rf /tmp/ps5-payload-sdk-src

        ok "ps5-payload-sdk instalado en $SDK_DIR"
    fi

    # Compilar el ELF loader
    info "Compilando el ELF loader..."
    export PS5_PAYLOAD_SDK="$SDK_DIR"
    if make -C elfldr/ 2>/dev/null; then
        cp elfldr/elfldr.elf payloads/
        ok "elfldr.elf compilado y copiado a payloads/"
    else
        err "La compilación falló. Comprueba que el SDK esté correctamente instalado."
    fi
else
    hdr "[ 4/4 ] ps5-payload-sdk (omitido)"
    info "Para compilar el ELF loader en C, ejecuta:"
    info "  ./setup.sh --sdk"
    info "O instala el SDK manualmente: https://github.com/ps5-payload-dev/sdk"
fi

# ── Resumen final ─────────────────────────────────────────────────────────────

echo ""
echo -e "${BLD}══════════════════════════════════════════${RST}"
echo -e "${BLD}  Setup completado${RST}"
echo -e "${BLD}══════════════════════════════════════════${RST}"
echo ""
echo -e "  ${BLD}Próximos pasos:${RST}"
echo ""
echo -e "  ${GRN}1.${RST} Levanta el servidor HTTP:"
echo -e "     ${CYN}python3 host/server.py${RST}"
echo ""
echo -e "  ${GRN}2.${RST} En la PS5, abre el browser y ve a:"
if [[ -n "$LOCAL_IP" ]]; then
    echo -e "     ${CYN}http://$LOCAL_IP:8000/exploit/index.html${RST}"
else
    echo -e "     ${CYN}http://TU_IP:8000/exploit/index.html${RST}"
fi
echo ""
echo -e "  ${GRN}3.${RST} Pulsa ▶ Ejecutar exploit y espera las 5 fases."
echo ""
echo -e "  ${GRN}4.${RST} Envía un payload:"
echo -e "     ${CYN}python3 tools/send_payload.py --host IP_PS5 --file payloads/mi.elf${RST}"
echo ""

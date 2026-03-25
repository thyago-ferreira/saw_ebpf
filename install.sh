#!/bin/bash
# ==============================================================
#  SAW_eBPF — Instalador Automático
#  Compatível com Debian 11+ (Bullseye) / Ubuntu 20.04+
# ==============================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "============================================================"
echo "  SAW_eBPF — Instalador Automático"
echo "============================================================"
echo ""

# --- Verificar root ---
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERRO] Execute como root: sudo bash install.sh${NC}"
    exit 1
fi

# --- Detectar distro ---
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
    VERSION="$VERSION_ID"
    echo -e "${GREEN}[OK]${NC} Sistema detectado: $PRETTY_NAME"
else
    echo -e "${YELLOW}[AVISO] Não foi possível detectar a distribuição.${NC}"
    DISTRO="unknown"
fi

# --- Passo 1: Atualizar sistema ---
echo ""
echo "[Passo 1/4] Atualizando lista de pacotes..."
echo "------------------------------------------------------------"
apt update -y

# --- Passo 2: Instalar headers do kernel ---
KVER=$(uname -r)
echo ""
echo "[Passo 2/4] Instalando cabeçalhos do kernel ($KVER)..."
echo "------------------------------------------------------------"

if dpkg -l | grep -q "linux-headers-$KVER"; then
    echo -e "${GREEN}[OK]${NC} linux-headers-$KVER já está instalado."
else
    if ! apt install -y "linux-headers-$KVER" 2>/dev/null; then
        echo -e "${YELLOW}[AVISO] Headers para $KVER não encontrados no repositório.${NC}"
        echo "        Isso acontece quando o kernel está desatualizado."
        echo ""
        read -p "  Deseja atualizar o sistema e reiniciar? (S/n): " RESP
        RESP=${RESP:-S}
        if [[ "$RESP" =~ ^[Ss]$ ]]; then
            echo "  Atualizando sistema..."
            apt upgrade -y
            echo ""
            echo -e "${YELLOW}============================================================${NC}"
            echo -e "${YELLOW}  REBOOT NECESSÁRIO${NC}"
            echo -e "${YELLOW}  Após reiniciar, execute novamente: sudo bash install.sh${NC}"
            echo -e "${YELLOW}============================================================${NC}"
            read -p "  Reiniciar agora? (S/n): " REBOOT
            REBOOT=${REBOOT:-S}
            if [[ "$REBOOT" =~ ^[Ss]$ ]]; then
                reboot
            fi
            exit 0
        else
            echo -e "${RED}[ERRO] Headers do kernel são obrigatórios. Instalação cancelada.${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}[OK]${NC} linux-headers-$KVER instalado."
fi

# --- Passo 3: Instalar BCC ---
echo ""
echo "[Passo 3/4] Instalando BCC (BPF Compiler Collection)..."
echo "------------------------------------------------------------"

# Debian usa python3-bpfcc, Ubuntu usa python3-bcc
BCC_INSTALLED=false

if dpkg -l | grep -q "python3-bpfcc\|python3-bcc"; then
    echo -e "${GREEN}[OK]${NC} BCC já está instalado."
    BCC_INSTALLED=true
fi

if [ "$BCC_INSTALLED" = false ]; then
    # Tentar python3-bpfcc primeiro (Debian 11+)
    if apt-cache show python3-bpfcc &>/dev/null; then
        apt install -y python3-bpfcc bpfcc-tools
        echo -e "${GREEN}[OK]${NC} python3-bpfcc instalado."
    # Fallback para python3-bcc (Ubuntu)
    elif apt-cache show python3-bcc &>/dev/null; then
        apt install -y python3-bcc bpfcc-tools
        echo -e "${GREEN}[OK]${NC} python3-bcc instalado."
    else
        echo -e "${RED}[ERRO] Pacote BCC não encontrado nos repositórios.${NC}"
        echo "        Tente adicionar o repositório manualmente:"
        echo "        sudo apt install -y bpfcc-tools python3-bpfcc"
        exit 1
    fi
fi

# --- Passo 4: Verificar instalação ---
echo ""
echo "[Passo 4/4] Verificando instalação..."
echo "------------------------------------------------------------"

# Testar import do BCC
if python3 -c "from bcc import BPF; print('BCC OK')" 2>/dev/null; then
    echo -e "${GREEN}[OK]${NC} Biblioteca BCC funcional."
else
    echo -e "${RED}[ERRO] BCC instalado mas import falhou.${NC}"
    echo "        Verifique com: python3 -c 'from bcc import BPF'"
    exit 1
fi

# Testar headers
if [ -d "/lib/modules/$KVER/build" ]; then
    echo -e "${GREEN}[OK]${NC} Cabeçalhos do kernel presentes."
else
    echo -e "${RED}[ERRO] Cabeçalhos do kernel não encontrados em /lib/modules/$KVER/build${NC}"
    exit 1
fi

# --- Pronto ---
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  SAW_eBPF instalado com sucesso!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  Para iniciar o monitoramento:"
echo ""
echo "    sudo python3 saw_ebpf.py            # Modo interativo"
echo "    sudo python3 saw_ebpf.py -i eth0    # Modo direto"
echo ""

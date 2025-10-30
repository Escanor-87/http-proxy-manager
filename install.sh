#!/bin/bash

# HTTP Proxy Manager
# Version: 1.0.0
# Author: Escanor
# Description: Professional HTTP proxy manager with Squid

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE="$CYAN"
NC='\033[0m'

# Configuration paths
MANAGER_DIR="/etc/http-proxy-manager"
PROFILES_FILE="$MANAGER_DIR/profiles.json"
BACKUP_DIR="$MANAGER_DIR/backups"
LOG_FILE="$MANAGER_DIR/manager.log"
SCRIPT_PATH="/usr/local/bin/http"
SQUID_CONFIG_DIR="/etc/squid"

# Script version
VERSION="1.0.0"

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Logging function
log_message() {
    local level=$1
    shift
    local message="$@"
    if [ -d "$MANAGER_DIR" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
    fi
}

# Check OS compatibility
check_os_compatibility() {
    if [ ! -f /etc/os-release ]; then
        print_error "Cannot detect OS. This script requires Ubuntu/Debian"
        exit 1
    fi
    
    . /etc/os-release
    if [[ ! "$ID" =~ ^(ubuntu|debian)$ ]]; then
        print_warning "This script is optimized for Ubuntu/Debian. Your OS: $ID"
        read -p "Continue anyway? [y/N]: " continue_install
        if [[ ! "$continue_install" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    log_message "INFO" "OS compatibility check passed: $ID $VERSION_ID"
}

# Check required commands
check_dependencies() {
    local missing_deps=()
    for cmd in apt systemctl ufw curl; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_error "Missing required commands: ${missing_deps[*]}"
        exit 1
    fi
}

# Backup profiles before operations
backup_profiles() {
    if [ ! -f "$PROFILES_FILE" ]; then
        return 0
    fi
    
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
    fi
    
    local backup_file="$BACKUP_DIR/profiles_$(date +%Y%m%d_%H%M%S).json"
    cp "$PROFILES_FILE" "$backup_file"
    
    # Keep only last 10 backups
    ls -t "$BACKUP_DIR"/profiles_*.json 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
    
    log_message "INFO" "Created backup: $backup_file"
}

# Validate port range
validate_port() {
    local port=$1
    if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

# Check if Squid is healthy
check_squid_health() {
    if ! systemctl is-active --quiet squid; then
        return 1
    fi
    
    # Check if Squid config is valid
    if ! squid -k parse &>/dev/null; then
        return 1
    fi
    
    return 0
}

# Check for updates from GitHub
check_for_updates() {
    local repo_url="https://raw.githubusercontent.com/Escanor-87/http-proxy-manager/main/install.sh"
    local current_version="$VERSION"
    
    # Try to fetch remote version
    local remote_version=$(curl -s --max-time 3 "$repo_url" | grep -m1 "^VERSION=" | cut -d'"' -f2 2>/dev/null)
    
    if [ -z "$remote_version" ]; then
        return 0  # Cannot check, skip silently
    fi
    
    if [ "$remote_version" != "$current_version" ]; then
        echo ""
        print_warning "Доступна новая версия: $remote_version (текущая: $current_version)"
        echo ""
        read -p "Хотите обновиться сейчас? [y/N]: " do_update
        
        if [[ "$do_update" =~ ^[Yy]$ ]]; then
            print_status "Скачивание обновления..."
            
            # Download new version
            local temp_file="/tmp/http-proxy-manager-update.sh"
            if curl -s -o "$temp_file" "$repo_url"; then
                chmod +x "$temp_file"
                
                # Replace current script
                cp "$temp_file" /usr/local/bin/http-proxy-manager.sh
                rm -f "$temp_file"
                
                print_success "Обновление установлено! Перезапуск..."
                log_message "INFO" "Updated from $current_version to $remote_version"
                
                sleep 1
                exec /usr/local/bin/http-proxy-manager.sh
            else
                print_error "Ошибка при скачивании обновления"
                return 1
            fi
        fi
    fi
}

init_manager() {
    if [ ! -d "$MANAGER_DIR" ]; then
        mkdir -p "$MANAGER_DIR"
        echo "[]" > "$PROFILES_FILE"
    fi
    setup_http_command
}

setup_http_command() {
    local target="/usr/local/bin/http-proxy-manager.sh"
    local link_path="/usr/local/bin/http"
    local source_script

    if [ -n "${BASH_SOURCE[0]}" ]; then
        source_script="$(readlink -f "${BASH_SOURCE[0]}")"
    else
        source_script="$(readlink -f "$0")"
    fi

    if [ ! -f "$target" ]; then
        cp "$source_script" "$target"
        chmod +x "$target"
        print_status "Скрипт скопирован в постоянное место: $target"
    fi

    if [ -L "$link_path" ] || [ -f "$link_path" ]; then
        rm -f "$link_path"
    fi

    ln -s "$target" "$link_path"
    chmod +x "$link_path"

    if [ ! -x "$link_path" ]; then
        print_warning "Не удалось создать команду 'http'"
    fi
}

install_dependencies() {
    print_status "Обновление пакетов и установка зависимостей..."
    
    if ! apt update > /dev/null 2>&1; then
        print_error "Ошибка при обновлении списка пакетов"
        log_message "ERROR" "apt update failed"
        exit 1
    fi
    
    if ! apt install -y squid apache2-utils jq iproute2 > /dev/null 2>&1; then
        print_error "Ошибка при установке пакетов"
        log_message "ERROR" "apt install failed"
        exit 1
    fi
    
    log_message "INFO" "Dependencies installed successfully"
    print_success "Зависимости установлены успешно"
}

generate_random_port() {
    while :; do
        port=$((RANDOM % 64512 + 1024))
        if ! ss -tulnp 2>/dev/null | awk '{print $4}' | grep -q ":$port" && ! is_port_used_by_profiles "$port"; then
            echo $port
            return
        fi
    done
}

is_port_used_by_profiles() {
    local check_port=$1
    if [ -f "$PROFILES_FILE" ]; then
        jq -r '.[].port' "$PROFILES_FILE" 2>/dev/null | grep -q "^$check_port$"
    else
        return 1
    fi
}

get_next_profile_number() {
    if [ ! -f "$PROFILES_FILE" ]; then
        echo 1
        return
    fi

    local max_num=0
    while IFS= read -r name; do
        if [[ "$name" =~ ^http-([0-9]+)$ ]]; then
            local num=${BASH_REMATCH[1]}
            if [ "$num" -gt "$max_num" ]; then
                max_num=$num
            fi
        fi
    done < <(jq -r '.[].name' "$PROFILES_FILE" 2>/dev/null)

    echo $((max_num + 1))
}

generate_squid_config() {
    cat > "/etc/squid/squid.conf" <<'EOF'
# HTTP Proxy Manager - Squid Configuration
# Version: 1.0.0
# Optimized for performance and security

# Access control
http_access allow all
http_port 3128

# Logging (disabled for privacy and performance)
access_log none
cache_log /dev/null
cache_store_log none

# Cache settings (disabled for privacy)
cache deny all
cache_mem 0 MB

# Performance tuning
dns_nameservers 8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1
dns_timeout 5 seconds
connect_timeout 30 seconds
read_timeout 30 seconds
request_timeout 30 seconds
persistent_request_timeout 60 seconds

# Connection pooling for better performance
client_lifetime 1 hour
pconn_timeout 120 seconds

# Memory and file descriptor limits
maximum_object_size_in_memory 512 KB
maximum_object_size 0 KB

# Rate limiting (connections per client IP)
# Uncomment to enable rate limiting:
# acl allsrc src all
# delay_pools 1
# delay_class 1 1
# delay_parameters 1 -1/-1
# delay_access 1 allow allsrc

# Security headers
forwarded_for delete
via off
follow_x_forwarded_for deny all
request_header_access X-Forwarded-For deny all
request_header_access Via deny all
request_header_access Cache-Control deny all
request_header_access Pragma deny all
request_header_access Connection deny all

# Prevent information leaks
httpd_suppress_version_string on
visible_hostname unknown

# ACL for safe ports
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl Safe_ports port 1025-65535
acl CONNECT method CONNECT

# Deny unsafe traffic (optional - uncomment for stricter security)
# http_access deny !Safe_ports
# http_access deny CONNECT !SSL_ports

EOF

    if [ -f "$PROFILES_FILE" ] && [ "$(jq length "$PROFILES_FILE")" -gt 0 ]; then
        while IFS= read -r profile; do
            local port=$(echo "$profile" | jq -r '.port')
            local name=$(echo "$profile" | jq -r '.name')
            local username=$(echo "$profile" | jq -r '.username')
            local has_auth=$(echo "$profile" | jq -r '.auth // true')

            if [ "$has_auth" = "true" ] && [ -n "$username" ] && [ "$username" != "null" ]; then
                cat >> "/etc/squid/squid.conf" <<EOF

# Профиль: $name (с авторизацией)
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/auth_${name}
auth_param basic realm HTTP Proxy
auth_param basic credentialsttl 24 hours
acl authenticated_users_${name} proxy_auth REQUIRED
http_access allow authenticated_users_${name}
http_port $port

EOF
            else
                cat >> "/etc/squid/squid.conf" <<EOF

# Профиль: $name (без авторизации)
http_port $port

EOF
            fi
        done < <(jq -c '.[]' "$PROFILES_FILE")
    fi
}

generate_random_string() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-12} | head -n 1
}

create_profile() {
    print_header "СОЗДАНИЕ НОВОГО HTTP PROXY ПРОФИЛЯ"
    echo ""

    local profile_num=$(get_next_profile_number)
    local profile_name="http-$profile_num"

    print_status "Название профиля: $profile_name"

    if profile_exists "$profile_name"; then
        print_error "Профиль с таким именем уже существует"
        return 1
    fi

    local port=$(generate_random_port)
    print_status "Выбран порт: $port"

    echo ""
    read -p "Требуется авторизация? [Y/n]: " need_auth

    local username=""
    local auth_pass=""
    local has_auth="true"

    if [[ "$need_auth" =~ ^[Nn]$ ]]; then
        has_auth="false"
        print_status "Профиль без авторизации"
    else
        username=$(generate_random_string 8)
        auth_pass=$(generate_random_string 12)

        print_status "Логин: $username"
        print_status "Пароль: $auth_pass"

        # Создание файла паролей для Squid
        htpasswd -bc "/etc/squid/auth_${profile_name}" "$username" "$auth_pass" > /dev/null 2>&1 || {
            print_error "Ошибка при создании файла паролей"
            log_message "ERROR" "htpasswd failed for profile $profile_name"
            return 1
        }
        chmod 644 "/etc/squid/auth_${profile_name}" || true
    fi

    save_profile "$profile_name" "$port" "$username" "$auth_pass" "$has_auth"

    print_status "Обновление конфигурации Squid..."
    generate_squid_config

    print_status "Настройка брандмауэра..."
    ufw allow proto tcp from 0.0.0.0/0 to any port "$port" > /dev/null 2>&1

    print_status "Перезапуск службы..."
    systemctl restart squid
    systemctl enable squid > /dev/null 2>&1

    if ! systemctl is-active --quiet squid; then
        print_error "Не удалось запустить службу Squid"
        return 1
    fi

    local external_ip=$(curl -4 -s ifconfig.me)

    echo ""
    print_header "ПРОФИЛЬ СОЗДАН УСПЕШНО"
    print_success "HTTP прокси-сервер '$profile_name' настроен!"
    echo ""
    echo -e "${BLUE}Параметры подключения:${NC}"
    echo "  Название: $profile_name"
    echo "  IP адрес: $external_ip"
    echo "  Порт: $port"
    echo "  Протокол: HTTP"

    if [ "$has_auth" = "true" ]; then
        echo "  Логин: $username"
        echo "  Auth: $auth_pass"
        echo ""
        echo -e "${BLUE}Форматы для антидетект браузеров :${NC}"
        echo "  $external_ip:$port:$username:$auth_pass"
        echo "  $username:$auth_pass@$external_ip:$port"
        echo "  http://$username:$auth_pass@$external_ip:$port"
        echo ""
        echo -e "${BLUE}Проверка работоспособности :${NC}"
        echo "  curl --proxy http://$username:$auth_pass@$external_ip:$port https://ifconfig.me"
    else
        echo "  Авторизация: Отключена "
        echo ""
        echo -e "${BLUE}Формат подключения :${NC}"
        echo "  $external_ip:$port"
        echo "  http://$external_ip:$port"
        echo ""
        echo -e "${BLUE}Проверка работоспособности :${NC}"
        echo "  curl --proxy http://$external_ip:$port https://ifconfig.me"
    fi
    echo ""
}

save_profile() {
    local name=$1
    local port=$2
    local username=$3
    local auth_pass=$4
    local has_auth=${5:-true}

    local new_profile
    if [ "$has_auth" = "true" ]; then
        new_profile=$(jq -n \
            --arg name "$name" \
            --arg port "$port" \
            --arg username "$username" \
            --arg password "$auth_pass" \
            --argjson auth true \
            --arg created "$(date -Iseconds)" \
            '{
                name: $name,
                port: ($port | tonumber),
                username: $username,
                password: $password,
                auth: $auth,
                created: $created
            }')
    else
        new_profile=$(jq -n \
            --arg name "$name" \
            --arg port "$port" \
            --argjson auth false \
            --arg created "$(date -Iseconds)" \
            '{
                name: $name,
                port: ($port | tonumber),
                username: null,
                password: null,
                auth: $auth,
                created: $created
            }')
    fi

    jq ". + [$new_profile]" "$PROFILES_FILE" > "$PROFILES_FILE.tmp" && mv "$PROFILES_FILE.tmp" "$PROFILES_FILE"
}

profile_exists() {
    local name=$1
    if [ -f "$PROFILES_FILE" ]; then
        jq -e ".[] | select(.name == \"$name\")" "$PROFILES_FILE" > /dev/null 2>&1
    else
        return 1
    fi
}

show_connections() {
    print_header "АКТИВНЫЕ HTTP PROXY ПОДКЛЮЧЕНИЯ "

    if [ ! -f "$PROFILES_FILE" ] || [ "$(jq length "$PROFILES_FILE")" -eq 0 ]; then
        print_warning "Нет созданных профилей "
        return
    fi

    local external_ip=$(curl -4 -s ifconfig.me 2>/dev/null || echo "N/A")
    local service_status=""

    if systemctl is-active --quiet squid; then
        service_status="${GREEN}АКТИВЕН ${NC}"
    else
        service_status="${RED}ОСТАНОВЛЕН ${NC}"
    fi

    echo ""
    echo -e "${CYAN}Список профилей :${NC}"
    echo ""

    local counter=1
    declare -a profile_names=()

    while IFS= read -r profile; do
        local name=$(echo "$profile" | jq -r '.name')
        local port=$(echo "$profile" | jq -r '.port')
        local has_auth=$(echo "$profile" | jq -r '.auth // true')

        profile_names+=("$name")

        if [ "$has_auth" = "true" ]; then
            echo -e "${CYAN}$counter.${NC} $name (порт: $port, с авторизацией )"
        else
            echo -e "${CYAN}$counter.${NC} $name (порт: $port, без авторизации )"
        fi
        ((counter++))
    done < <(jq -c '.[]' "$PROFILES_FILE")

    echo ""
    echo -e "${CYAN}0.${NC} Назад в главное меню "
    echo ""

    read -p "Выберите профиль для просмотра  (0-$((counter-1))): " selection

    if [[ "$selection" == "0" ]]; then
        return
    fi

    if ! [[ "$selection" =~ ^[1-9][0-9]*$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -ge $counter ]; then
        print_error "Неверный выбор "
        sleep 1
        return
    fi

    local selected_profile=$(echo "${profile_names[$((selection-1))]}")
    local profile_data=$(jq ".[] | select(.name == \"$selected_profile\")" "$PROFILES_FILE")

    local name=$(echo "$profile_data" | jq -r '.name')
    local port=$(echo "$profile_data" | jq -r '.port')
    local username=$(echo "$profile_data" | jq -r '.username')
    local auth_pass=$(echo "$profile_data" | jq -r '.password')
    local created=$(echo "$profile_data" | jq -r '.created')
    local has_auth=$(echo "$profile_data" | jq -r '.auth // true')

    clear
    print_header "ИНФОРМАЦИЯ О ПРОФИЛЕ: $name"
    echo ""
    echo -e "${BLUE}Параметры подключения:${NC}"
    echo "  Название: $name"
    echo "  IP адрес: $external_ip"
    echo "  Порт: $port"
    echo "  Протокол: HTTP"

    if [ "$has_auth" = "true" ]; then
        echo "  Логин: $username"
        echo "  Auth: $auth_pass"
    else
        echo "  Авторизация: Отключена "
    fi

    echo -e "  Статус: $service_status"
    echo "  Создан: $created"
    echo ""

    if [ "$has_auth" = "true" ]; then
        echo -e "${BLUE}Форматы для антидетект браузеров :${NC}"
        echo "  $external_ip:$port:$username:$auth_pass"
        echo "  $username:$auth_pass@$external_ip:$port"
        echo "  http://$username:$auth_pass@$external_ip:$port"
        echo ""
        echo -e "${BLUE}Проверка работоспособности :${NC}"
        echo "  curl --proxy http://$username:$auth_pass@$external_ip:$port https://ifconfig.me"
    else
        echo -e "${BLUE}Формат подключения :${NC}"
        echo "  $external_ip:$port"
        echo "  http://$external_ip:$port"
        echo ""
        echo -e "${BLUE}Проверка работоспособности :${NC}"
        echo "  curl --proxy http://$external_ip:$port https://ifconfig.me"
    fi
    echo ""

    read -p "Нажмите Enter для возврата к списку..."
    clear
    show_connections
}

delete_profile() {
    print_header "УДАЛЕНИЕ HTTP PROXY ПРОФИЛЯ "

    if [ ! -f "$PROFILES_FILE" ] || [ "$(jq length "$PROFILES_FILE")" -eq 0 ]; then
        print_warning "Нет профилей для удаления "
        return
    fi

    echo ""
    echo "Доступные профили :"
    jq -r '.[] | "  - \(.name) (порт: \(.port))"' "$PROFILES_FILE"
    echo ""

    read -p "Введите название профиля для удаления: " profile_name

    if [ -z "$profile_name" ]; then
        print_warning "Название профиля не указано "
        return
    fi

    if ! profile_exists "$profile_name"; then
        print_error "Профиль  '$profile_name' не найден "
        return
    fi

    local profile_data=$(jq ".[] | select(.name == \"$profile_name\")" "$PROFILES_FILE")
    local port=$(echo "$profile_data" | jq -r '.port')

    echo ""
    read -p "Вы уверены, что хотите удалить профиль  '$profile_name'? [y/N]: " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_warning "Удаление отменено "
        return
    fi

    print_status "Удаление профиля  '$profile_name'..."

    # Удаление файла паролей
    rm -f "/etc/squid/auth_${profile_name}"

    ufw delete allow "$port/tcp" > /dev/null 2>&1

    jq "del(.[] | select(.name == \"$profile_name\"))" "$PROFILES_FILE" > "$PROFILES_FILE.tmp" && mv "$PROFILES_FILE.tmp" "$PROFILES_FILE"

    print_status "Обновление конфигурации Squid..."
    generate_squid_config

    if [ "$(jq length "$PROFILES_FILE")" -gt 0 ]; then
        systemctl restart squid
    else
        print_warning "Это был последний профиль . Остановка службы Squid."
        systemctl stop squid
    fi

    print_success "Профиль  '$profile_name' успешно удалён "
}

uninstall_manager() {
    print_header "ПОЛНОЕ УДАЛЕНИЕ HTTP PROXY МЕНЕДЖЕРА"
    echo ""
    echo -e "${RED}ВНИМАНИЕ: Это действие удалит ВСЕ профили и конфигурации!${NC}"
    echo ""

    read -p "Вы уверены? Введите 'YES' для подтверждения: " confirm

    if [ "$confirm" != "YES" ]; then
        print_warning "Удаление отменено "
        return
    fi

    print_status "Удаление всех профилей и конфигураций..."

    systemctl stop squid 2>/dev/null
    systemctl disable squid 2>/dev/null

    if [ -f "$PROFILES_FILE" ]; then
        while IFS= read -r profile; do
            local port=$(echo "$profile" | jq -r '.port')
            local name=$(echo "$profile" | jq -r '.name')

            rm -f "/etc/squid/auth_${name}"
            ufw delete allow "$port/tcp" > /dev/null 2>&1
        done < <(jq -c '.[]' "$PROFILES_FILE")
    fi

    rm -rf "$MANAGER_DIR"
    rm -f "/etc/squid/squid.conf"
    rm -f "/etc/squid/auth_"*
    rm -f "$SCRIPT_PATH"
    rm -f /usr/local/bin/http-proxy-manager.sh

    DEBIAN_FRONTEND=noninteractive apt --purge remove -y squid apache2-utils > /dev/null 2>&1

    print_success "HTTP Proxy менеджер полностью удалён "
}

show_main_menu() {
    while true; do
        clear
        print_header "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        print_header "    HTTP PROXY MANAGER by Escanor"
        print_header "    Version: $VERSION"
        print_header "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo -e "${CYAN}1.${NC} Показать все подключения "
        echo -e "${CYAN}2.${NC} Создать новое подключение "
        echo ""
        echo -e "${CYAN}3.${NC} Удалить подключение "
        echo -e "${CYAN}4.${NC} Удалить менеджер и все конфигурации "
        echo ""
        echo -e "${CYAN}0.${NC} Выход "
        echo ""
        echo -e "\▸ Быстрый запуск: ${CYAN}http${NC} доступен из любой точки системы "
        echo ""

        read -p "Выберите пункт меню  (0-4): " choice

        case $choice in
            1)
                clear
                show_connections
                echo ""
                read -p "Нажмите Enter для продолжения..."
                ;;
            2)
                clear
                create_profile
                echo ""
                read -p "Нажмите Enter для продолжения..."
                ;;
            3)
                clear
                delete_profile
                echo ""
                read -p "Нажмите Enter для продолжения..."
                ;;
            4)
                clear
                uninstall_manager
                exit 0
                ;;
            0)
                echo ""
                print_status "До свидания !"
                exit 0
                ;;
            *)
                print_error "Неверный выбор. Попробуйте снова."
                sleep 1
                ;;
        esac
    done
}

main() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Этот скрипт должен быть запущен с правами root"
        exit 1
    fi

    if [ ! -d "$MANAGER_DIR" ]; then
        print_status "Установка HTTP PROXY MANAGER v$VERSION"
        echo ""
        
        # Check OS compatibility and dependencies
        check_os_compatibility
        check_dependencies
        
        install_dependencies
        init_manager
        generate_squid_config
        setup_http_command
        rm -f /root/install.sh

        echo ""
        print_success "Менеджер HTTP прокси успешно установлен !"
        echo ""

        read -p "Создать первый профиль сейчас ? [Y/n]: " create_first

        # ИСПРАВЛЕНО: профиль создаётся только при явном согласии
        if [[ "$create_first" =~ ^[Yy]$ ]] || [ -z "$create_first" ]; then
            clear
            create_profile
            echo ""
            read -p "Нажмите Enter для продолжения..."
        fi
    else
        setup_http_command
    fi

    show_main_menu
}

if [ "${1:-}" = "menu" ] || [ "${1:-}" = "" ]; then
    main
elif [ "${1:-}" = "list" ]; then
    show_connections
elif [ "${1:-}" = "create" ]; then
    if [[ $EUID -ne 0 ]]; then
        print_error "Этот скрипт должен быть запущен с правами root"
        exit 1
    fi
    init_manager
    create_profile
elif [ "$1" = "delete" ]; then
    if [[ $EUID -ne 0 ]]; then
        print_error "Этот скрипт должен быть запущен с правами root"
        exit 1
    fi
    init_manager
    delete_profile
else
    echo "Использование: http [menu|list|create|delete]"
    echo "  list   - показать все подключения"
    echo "  create - создать новое подключение"
    echo "  delete - удалить подключение"
fi
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE="$CYAN"
NC='\033[0m'

MANAGER_DIR="/etc/http-proxy-manager"
PROFILES_FILE="$MANAGER_DIR/profiles.json"
SCRIPT_PATH="/usr/local/bin/http"
SQUID_CONFIG_DIR="/etc/squid"

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
    apt update > /dev/null 2>&1 && apt install -y squid apache2-utils jq iproute2 > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        print_error "Ошибка при установке пакетов"
        exit 1
    fi
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
# Основные настройки Squid
http_access allow all
http_port 3128

# Отключение логирования
access_log none
cache_log /dev/null
cache_store_log none

# Отключение кэширования
cache deny all

# Настройки производительности
dns_nameservers 8.8.8.8 8.8.4.4

# Безопасность
forwarded_for delete
via off
follow_x_forwarded_for deny all
request_header_access X-Forwarded-For deny all
request_header_access Via deny all
request_header_access Cache-Control deny all

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
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords_${name}
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
    local password=""
    local has_auth="true"

    if [[ "$need_auth" =~ ^[Nn]$ ]]; then
        has_auth="false"
        print_status "Профиль без авторизации"
    else
        username="user$profile_num"
        password=$(generate_random_string)

        print_status "Логин: $username"
        print_status "Пароль: $password"

        # Создание файла паролей для Squid
        htpasswd -bc "/etc/squid/passwords_${profile_name}" "$username" "$password" > /dev/null 2>&1
        chmod 644 "/etc/squid/passwords_${profile_name}"
    fi

    save_profile "$profile_name" "$port" "$username" "$password" "$has_auth"

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
        echo "  Пароль: $password"
        echo ""
        echo -e "${BLUE}Форматы для антидетект браузеров :${NC}"
        echo "  $external_ip:$port:$username:$password"
        echo "  $username:$password@$external_ip:$port"
        echo "  http://$username:$password@$external_ip:$port"
        echo ""
        echo -e "${BLUE}Проверка работоспособности :${NC}"
        echo "  curl --proxy http://$username:$password@$external_ip:$port https://ifconfig.me"
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
    local password=$4
    local has_auth=${5:-true}

    local new_profile
    if [ "$has_auth" = "true" ]; then
        new_profile=$(jq -n \
            --arg name "$name" \
            --arg port "$port" \
            --arg username "$username" \
            --arg password "$password" \
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
    local password=$(echo "$profile_data" | jq -r '.password')
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
        echo "  Пароль: $password"
    else
        echo "  Авторизация: Отключена "
    fi

    echo -e "  Статус: $service_status"
    echo "  Создан: $created"
    echo ""

    if [ "$has_auth" = "true" ]; then
        echo -e "${BLUE}Форматы для антидетект браузеров :${NC}"
        echo "  $external_ip:$port:$username:$password"
        echo "  $username:$password@$external_ip:$port"
        echo "  http://$username:$password@$external_ip:$port"
        echo ""
        echo -e "${BLUE}Проверка работоспособности :${NC}"
        echo "  curl --proxy http://$username:$password@$external_ip:$port https://ifconfig.me"
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
    rm -f "/etc/squid/passwords_${profile_name}"

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

            rm -f "/etc/squid/passwords_${name}"
            ufw delete allow "$port/tcp" > /dev/null 2>&1
        done < <(jq -c '.[]' "$PROFILES_FILE")
    fi

    rm -rf "$MANAGER_DIR"
    rm -f "/etc/squid/squid.conf"
    rm -f "/etc/squid/passwords_"*
    rm -f "$SCRIPT_PATH"
    rm -f /usr/local/bin/http-proxy-manager.sh

    DEBIAN_FRONTEND=noninteractive apt --purge remove -y squid apache2-utils > /dev/null 2>&1

    print_success "HTTP Proxy менеджер полностью удалён "
}

show_main_menu() {
    while true; do
        clear
        print_header "HTTP PROXY MANAGER by distillium"
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
        print_status "Установка HTTP PROXY MANAGER"
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

if [ "$1" = "menu" ] || [ "$1" = "" ]; then
    main
elif [ "$1" = "list" ]; then
    show_connections
elif [ "$1" = "create" ]; then
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
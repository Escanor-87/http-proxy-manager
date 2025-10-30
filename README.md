# HTTP Proxy Manager

Простой и удобный менеджер для управления HTTP прокси-серверами на базе Squid.

## 🚀 Возможности

- ✅ Автоматическая установка и настройка Squid
- 🔐 Поддержка авторизации (логин/пароль)
- 🚫 Прокси без авторизации
- 📝 Управление множественными профилями
- 🎯 Автоматический выбор свободных портов
- 🔥 Настройка брандмауэра (ufw)
- 💾 Хранение конфигураций в JSON
- 🎨 Цветной интерфейс CLI
- ⚡ Быстрый доступ через команду `http`

## 📋 Требования

- **ОС:** Ubuntu/Debian или другой Linux с поддержкой apt
- **Права:** root (sudo)
- **Пакеты:** Автоматически устанавливаются:
  - squid
  - apache2-utils
  - jq
  - iproute2

## 🛠 Установка

```bash
# Скачать скрипт
wget https://raw.githubusercontent.com/Escanor-87/http-proxy-manager/main/install.sh

# Или с помощью curl
curl -O https://raw.githubusercontent.com/Escanor-87/http-proxy-manager/main/install.sh

# Дать права на выполнение
chmod +x install.sh

# Запустить установку
sudo ./install.sh
```

## 📖 Использование

После установки доступна команда `http` из любой точки системы:

```bash
# Главное меню
sudo http

# Показать все подключения
sudo http list

# Создать новый профиль
sudo http create

# Удалить профиль
sudo http delete
```

## 🎯 Примеры использования

### Создание профиля с авторизацией

```bash
sudo http create
```

Скрипт автоматически:
- Выберет свободный порт
- Сгенерирует логин и пароль
- Настроит Squid
- Откроет порт в брандмауэре
- Покажет готовые параметры подключения

### Форматы подключения

Для антидетект браузеров:
```
45.123.45.67:8080:user1:SecureP@ss
user1:SecureP@ss@45.123.45.67:8080
http://user1:SecureP@ss@45.123.45.67:8080
```

### Проверка работоспособности

```bash
curl --proxy http://user1:SecureP@ss@45.123.45.67:8080 https://ifconfig.me
```

## 🖥 Главное меню

```
HTTP PROXY MANAGER by distillium

1. Показать все подключения
2. Создать новое подключение

3. Удалить подключение
4. Удалить менеджер и все конфигурации

0. Выход

▸ Быстрый запуск: http доступен из любой точки системы
```

## 📂 Структура файлов

```
/etc/http-proxy-manager/
├── profiles.json              # База профилей
/etc/squid/
├── squid.conf                 # Конфигурация Squid
├── auth_http-1                # Учетные данные профиля http-1
├── auth_http-2                # Учетные данные профиля http-2
/usr/local/bin/
├── http-proxy-manager.sh      # Основной скрипт
└── http                       # Символическая ссылка
```

## 🔧 Технические детали

### Безопасность

- Отключено логирование (access_log, cache_log)
- Отключено кэширование
- Удалены заголовки X-Forwarded-For и Via
- Пароли хранятся в зашифрованном виде (htpasswd)

### Настройки Squid

```conf
# Основные настройки
http_access allow all
dns_nameservers 8.8.8.8 8.8.4.4

# Безопасность
forwarded_for delete
via off
follow_x_forwarded_for deny all
```

### Диапазон портов

Автоматически выбираются свободные порты из диапазона: **1024-65535**

## 🗑 Удаление

```bash
sudo http
# Выбрать пункт 4: "Удалить менеджер и все конфигурации"
# Ввести YES для подтверждения
```

Или вручную:

```bash
# Остановить службу
sudo systemctl stop squid

# Удалить файлы
sudo rm -rf /etc/http-proxy-manager
sudo rm -f /etc/squid/squid.conf
sudo rm -f /etc/squid/auth_*
sudo rm -f /usr/local/bin/http-proxy-manager.sh
sudo rm -f /usr/local/bin/http

# Удалить пакеты (опционально)
sudo apt purge -y squid apache2-utils
```

## 🔧 Troubleshooting

### Squid не запускается

```bash
# Проверить статус службы
sudo systemctl status squid

# Проверить конфигурацию
sudo squid -k parse

# Проверить логи
sudo journalctl -u squid -n 50

# Перезапустить службу
sudo systemctl restart squid
```

### Прокси не работает

```bash
# Проверить открытые порты
sudo ss -tulnp | grep squid

# Проверить правила файрвола
sudo ufw status

# Тестирование подключения
curl -v --proxy http://USER:PASS@YOUR_IP:PORT https://ifconfig.me

# Проверить внешний IP
curl -4 ifconfig.me
```

### Ошибка авторизации

```bash
# Проверить файл учетных данных
sudo ls -la /etc/squid/auth_*

# Пересоздать файл учетных данных
sudo htpasswd -bc /etc/squid/auth_http-1 YOUR_USER YOUR_PASS

# Перезапустить Squid
sudo systemctl restart squid
```

### Высокая нагрузка на сервер

```bash
# Проверить активные подключения
sudo netstat -an | grep ESTABLISHED | wc -l

# Проверить использование ресурсов
top -p $(pgrep squid)

# Включить rate limiting в /etc/squid/squid.conf
# Раскомментировать строки:
# acl allsrc src all
# delay_pools 1
# delay_class 1 1
# delay_parameters 1 -1/-1
# delay_access 1 allow allsrc
```

### Резервное копирование профилей

```bash
# Автоматические бэкапы создаются в:
ls -la /etc/http-proxy-manager/backups/

# Восстановить из бэкапа
sudo cp /etc/http-proxy-manager/backups/profiles_*.json /etc/http-proxy-manager/profiles.json
sudo http  # Перезапустить менеджер
```

### Проверка логов менеджера

```bash
# Просмотр логов
sudo tail -f /etc/http-proxy-manager/manager.log

# Очистка логов (если файл стал слишком большим)
sudo truncate -s 0 /etc/http-proxy-manager/manager.log
```

## 📚 Best Practices

### Безопасность

1. **Используйте сложные учетные данные**: Автоматически генерируются 12-символьные пароли
2. **Ограничьте доступ по IP**: Настройте файрвол для разрешения только доверенных IP
3. **Регулярно обновляйте систему**: `sudo apt update && sudo apt upgrade`
4. **Мониторинг подключений**: Проверяйте активные соединения регулярно
5. **Rate limiting**: Включайте ограничение скорости для защиты от злоупотреблений

### Производительность

1. **Оптимальное количество профилей**: Рекомендуется до 50 профилей на один сервер
2. **DNS-серверы**: Используются быстрые DNS (Google, Cloudflare)
3. **Таймауты**: Настроены оптимальные значения для стабильной работы
4. **Без кэширования**: Отключено для приватности и экономии места

### Мониторинг

```bash
# Регулярно проверяйте работоспособность
watch -n 5 'sudo systemctl is-active squid'

# Мониторинг портов
watch -n 5 'sudo ss -tulnp | grep squid'

# Проверка использования CPU/RAM
htop
```

### Обслуживание

```bash
# Еженедельная проверка
sudo http list

# Ежемесячная очистка старых бэкапов (автоматически сохраняются последние 10)
ls -la /etc/http-proxy-manager/backups/

# Проверка обновлений Squid
sudo apt list --upgradable | grep squid
```

## ❓ FAQ

**Q: Можно ли использовать на других дистрибутивах?**  
A: Скрипт оптимизирован для Ubuntu/Debian. При запуске на других дистрибутивах появится предупреждение с возможностью продолжить.

**Q: Сколько профилей можно создать?**  
A: Технически до ~64000 (количество доступных портов), но рекомендуется до 50 профилей на один сервер для оптимальной производительности.

**Q: Безопасно ли отключать логирование?**  
A: Да, это стандартная практика для приватных прокси. Логи занимают много места и не всегда нужны. Системные логи менеджера сохраняются в `/etc/http-proxy-manager/manager.log`.

**Q: Поддерживается ли HTTPS?**  
A: Скрипт настраивает HTTP-прокси, но он может проксировать HTTPS-трафик методом CONNECT.

**Q: Можно ли использовать с IPv6?**  
A: Текущая версия работает только с IPv4. Поддержка IPv6 планируется в будущих версиях.

**Q: Где хранятся бэкапы?**  
A: Автоматические бэкапы профилей создаются при каждой операции в `/etc/http-proxy-manager/backups/`. Хранятся последние 10 бэкапов.

**Q: Как включить rate limiting?**  
A: Rate limiting закомментирован в конфигурации Squid. Раскомментируйте соответствующие строки в `/etc/squid/squid.conf` и перезапустите службу.

## 📝 Лицензия

MIT License - свободное использование, модификация и распространение.

## 👤 Автор

**distillium**

## 🤝 Вклад

Приветствуются pull requests и issue reports!

1. Fork проекта
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## ⭐ Поддержка

Если проект был полезен, поставьте звезду ⭐

---

**Важно:** Используйте прокси-серверы ответственно и в соответствии с законодательством вашей страны.

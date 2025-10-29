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
45.123.45.67:8080:user1:password123
user1:password123@45.123.45.67:8080
http://user1:password123@45.123.45.67:8080
```

### Проверка работоспособности

```bash
curl --proxy http://user1:password123@45.123.45.67:8080 https://ifconfig.me
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
├── passwords_http-1           # Пароли для профиля http-1
├── passwords_http-2           # Пароли для профиля http-2
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
sudo rm -f /etc/squid/passwords_*
sudo rm -f /usr/local/bin/http-proxy-manager.sh
sudo rm -f /usr/local/bin/http

# Удалить пакеты (опционально)
sudo apt purge -y squid apache2-utils
```

## ❓ FAQ

**Q: Можно ли использовать на других дистрибутивах?**  
A: Скрипт оптимизирован для Ubuntu/Debian. Для CentOS/RHEL потребуется адаптация (yum вместо apt).

**Q: Сколько профилей можно создать?**  
A: Ограничено только количеством доступных портов (~64000).

**Q: Безопасно ли отключать логирование?**  
A: Да, это стандартная практика для приватных прокси. Логи занимают много места и не всегда нужны.

**Q: Поддерживается ли HTTPS?**  
A: Скрипт настраивает HTTP-прокси, но он может проксировать HTTPS-трафик методом CONNECT.

**Q: Можно ли использовать с IPv6?**  
A: Текущая версия работает только с IPv4.

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

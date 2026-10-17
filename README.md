# Защита информации

Лабораторные работы по дисциплине «Защита информации»: программы на Python 3 (только стандартная библиотека) и отчёты.

> Астраханский государственный технический университет, кафедра АСОИУ, 2026
>
> Выполнил: студент Генералов В. В., группа ЗИНРб-51

## Лабораторные работы

| № | Тема | Программа | Отчёт |
|---|---|---|---|
| 1 | Протокол Диффи-Хеллмана | [`lab1/dh.py`](lab1/dh.py) | [`lab1/report.pdf`](lab1/report.pdf) |
| 2 | Алгоритм шифрования RSA | [`lab2/rsa.py`](lab2/rsa.py) | [`lab2/report.pdf`](lab2/report.pdf) |
| 3 | Разработка алгоритма хэш-функции | [`lab3/myhash.py`](lab3/myhash.py) | [`lab3/report.pdf`](lab3/report.pdf) |
| 4 | Реализация электронной цифровой подписи | [`lab4/signature.py`](lab4/signature.py) | [`lab4/report.pdf`](lab4/report.pdf) |
| 5 | Комплексное обеспечение безопасности менеджера учётных записей | [`lab5/manager.py`](lab5/manager.py) | [`lab5/report.pdf`](lab5/report.pdf) |

В папке каждой работы: программа, `README.md` с описанием и результатами, отчёт в форматах `.docx` и `.pdf`.

## Запуск

```bash
python3 lab1/dh.py
python3 lab2/rsa.py
python3 lab3/myhash.py
python3 lab4/signature.py       # использует соседние lab2/rsa.py и lab3/myhash.py
python3 lab5/manager.py         # графическое окно (tkinter); python3 lab5/storage.py — автотест без GUI
python3 launcher.py             # меню всех работ; --selftest — проверка всех работ без окон
```

Программы работ 1–4 работают в консоли через меню, работа 5 — в графическом окне. Нужен Python 3.8 или новее, сторонние пакеты не используются (для работы 5 нужен модуль `tkinter` из стандартной поставки Python; в некоторых дистрибутивах Linux он ставится пакетом `python3-tk`).

## Готовые исполняемые файлы

Все пять работ собраны в один исполняемый файл на систему, Python для него не нужен. Файлы лежат в разделе [Releases](https://github.com/ASTU-StudyHub/INFOSEC/releases/latest) репозитория: их собирает и публикует GitHub Actions ([`.github/workflows/build.yml`](.github/workflows/build.yml)) при push тега `v*`; при ручном запуске сборки (Actions → «Сборка исполняемых файлов» → Run workflow) файлы попадают в артефакты запуска.

| Система | Файл |
|---|---|
| Windows 10 и 11 (x64) | [`INFOSEC-windows.exe`](https://github.com/ASTU-StudyHub/INFOSEC/releases/latest/download/INFOSEC-windows.exe) |
| macOS, Apple Silicon и Intel | [`INFOSEC-macos`](https://github.com/ASTU-StudyHub/INFOSEC/releases/latest/download/INFOSEC-macos) |
| Linux x86_64 (glibc 2.35 и новее: Ubuntu 22.04, Debian 12 и т. п.) | [`INFOSEC-linux`](https://github.com/ASTU-StudyHub/INFOSEC/releases/latest/download/INFOSEC-linux) |

Без аргументов файл открывает меню работ: номер — запуск работы, после её завершения меню показывается снова, `0` — выход. Работу можно запустить и сразу, с её собственными аргументами:

```bash
./INFOSEC-macos                 # меню работ; в Windows — INFOSEC-windows.exe (двойной щелчок или из терминала)
./INFOSEC-macos lab3            # сразу работа 3
./INFOSEC-macos lab5 ПАПКА      # работа 5 с другой папкой данных
./INFOSEC-macos --selftest      # проверка всех работ без окон
./INFOSEC-macos --help          # справка
```

Первый запуск:

- **macOS** — сначала `chmod +x INFOSEC-macos`. Файл не подписан Apple, и Gatekeeper остановит первый запуск: откройте файл через контекстное меню Finder → «Открыть» (в macOS 15 и новее — разрешите запуск в «Системные настройки» → «Конфиденциальность и безопасность») или снимите карантин: `xattr -d com.apple.quarantine INFOSEC-macos`.
- **Windows** — SmartScreen предупредит о неизвестном издателе: «Подробнее» → «Выполнить в любом случае».
- **Linux** — `chmod +x INFOSEC-linux` и запуск из терминала: `./INFOSEC-linux`; для окна работы 5 нужен графический сеанс.

При каждом запуске файл распаковывается во временную папку, на это уходит пара секунд. Данные работы 5 (БД, хэш-сумма, журнал) хранятся в домашней папке пользователя: `~/.infosec/lab5`, в Windows — `%USERPROFILE%\.infosec\lab5`.

Из исходников то же меню запускается командой `python3 launcher.py` с теми же аргументами; данные работы 5 при этом, как и при запуске `lab5/manager.py`, хранятся в `lab5/data`.

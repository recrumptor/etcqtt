# Лицензии и происхождение компонентов

| Компонент | Откуда | Лицензия |
|---|---|---|
| Ядро клиента (`csqtt-core`, upstream `client`) | [amurcanov/csqtt](https://github.com/amurcanov/csqtt), собирается из исходников в CI | PolyForm Noncommercial 1.0.0 |
| `luci-app-csqtt` (JS-страницы, rpcd-бэкенд ucode, ACL, меню, `migrate-shared-settings.sh`) | файлы, предоставленные владельцем репозитория (извлечены из пакета `luci-app-csqtt` 1.1.0) | PolyForm Noncommercial 1.0.0 (заголовки SPDX сохранены) |
| `luci-i18n-csqtt-ru` (`csqtt.ru.lmo`) | то же | PolyForm Noncommercial 1.0.0 |
| `csqtt/files/etc/*` (init-скрипт, шаблон UCI, logrotate) | то же | PolyForm Noncommercial 1.0.0 |
| `wrapper/` (служба `csqtt`: супервизор, TUN, пул профилей, CAPTCHA-помощник, CLI) | написан с нуля в этом репозитории | MIT |

**Required Notice** (требование PolyForm Noncommercial): Copyright 2026 amurcanov.

Итоговые пакеты `.ipk`/`.apk` содержат ядро и файлы под PolyForm Noncommercial, поэтому
**пакеты в целом — только для некоммерческого использования**. Лицензия не даёт права
использовать их в коммерческих целях; условия — в тексте
<https://polyformproject.org/licenses/noncommercial/1.0.0/>.

## Как написана обёртка

`wrapper/` — самостоятельная реализация. Её интерфейс восстановлен из:
* публичного кода ядра upstream (`--tun-uds`, протокол событий `__CSQTT_EVENT__`,
  `CAPTCHA_SOLVE` / `CAPTCHA_RESULT`, `VK_JS_BOOTSTRAP`, `HASH_CHECK`);
* потребителей: init-скрипта, rpcd-бэкенда и JS-страниц LuCI (команды CLI, схема
  `status.json`, API помощника CAPTCHA, UCI-схема).

Закрытый бинарник стороннего автора для написания обёртки не использовался и не декомпилировался
(его строки просматривались только при проверке безопасности); код оттуда не копировался.

## Необязательные сторонние патчи

* `patches/core-small-udp-pin.patch` — автор SanityProtocol (коммит `dda3357`, ветка `small-udp-pin-fix` репозитория
  SanityProtocol/csqtt-rebirth, [PR ttrroyy/csqttr#2](https://github.com/ttrroyy/csqttr/pull/2)). Меняет код ядра
  (`rust-client/dispatcher.rs`), поэтому на него распространяется лицензия ядра — PolyForm Noncommercial 1.0.0.

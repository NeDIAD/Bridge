# Bridge 0.4.0 — current patch synchronization

The signal-parking design below describes historical versions 0.3.x. It is
superseded and removed from the production source in 0.4.0.

A live SRCDS task reported SigBlk=fffffffe7ffbfeff: all RT signals were blocked.
A queued RT notification cannot park that task, so the old all-thread handshake
correctly refused code writes but could not install Bridge on this server.

Current implementation patches ONLY Verify, Register and End call sites, all
inside the same native auth mutex (Steamclient RVA 0x22ec278). The full normal
CFG lock proof is checked by tests/verify_native_lock.py. Runtime checks compare
complete original Begin/End bodies before installation and again under the
mutex; this rejects altered code which would invalidate that proof. While the
installer owns the mutex, other auth callers cannot execute the affected CALLs.
The native acquisition/release path and full function bytes, not only return
values from mocked locks, are the basis of this exclusion argument.

Before writes, query/register/preflight Linux PRIVATE_EXPEDITED_SYNC_CORE.
After ALL three calls are copied, execute SYNC_CORE before releasing the native
mutex. Signal masks are irrelevant to this kernel synchronization. Acquisition
is bounded to 500 ms. Unsupported/denied membarrier, busy mutex, changed code or
failed RWX preflight cause refusal before writes. Post-write synchronization or
RX restore failure retains the complete hook set, refuses unload and reports
that a process restart is required. OS failures after commit do not provide a
fully successful synchronization/protection postcondition; they are not treated
as a running/successful plugin. Kernel support is required (Linux 4.16+).

The callback dispatcher is no longer patched. An independent game-server
CCallbackBase observer is registered through SteamAPI_RegisterCallback after
host initialization. Its vtable has Run, Run-with-call-result, payload-size;
i386 size is 12 bytes, game-server flag is 2, callback ID 143, payload is 20
bytes. The observer logs only; original callbacks remain owned by Steam API and
continue to the engine/other listeners unchanged.

The previous UserHasLicenseForApp fallback is also NOT installed in 0.4.0:
its call is outside this mutex and cannot be included in the same proof.
Native license queries remain unchanged. Consumers relying on a redirected
730->4465480 license lookup do not get that behavior in this version. Auth
identity and cross-AppId duplicate checks remain in scope and tested.

Compiled emulation passes native-lock exclusion checks, supported/denied
SYNC_CORE, mutex timeout, exact-body mismatch, blocked-signal peer, callback
observer ABI/payload, and post-write failure lifetime checks. The kernel
harness now uses 16 real signal-blocking workers behind a pthread mutex and
100 SYNC_CORE cycles. It BUILDS for Linux i386 but has NOT RUN on this host.
The server operator subsequently confirmed live SRCDS authorization with a real
Steam callback, both cross-AppId duplicate orders, reconnect/map changes and
plugin data. Those server checks and the Windows auth/lifecycle thread tests do
not replace the standalone native kernel run.

References:
- https://man7.org/linux/man-pages/man2/membarrier.2.html
- https://partner.steamgames.com/doc/sdk/api
- https://partner.steamgames.com/doc/api/steam_gameserver

---

Historical 0.3.0 review follows:
# Bridge 0.3.0 — проверка гонок и исправления

Область: маршрутизация 730/4465480, нативный список auth sessions, TLS,
публикация API, жизненный цикл Metamod, установка машинных хуков и ошибки ОС.
Проверка выполнена вручную по исходникам и поставленным бинарникам; это не
результат формального облачного сканирования Codex Security.

## Найденные проблемы

| Участок 0.2.0 | Проблема | Исправление 0.3.0 |
|---|---|---|
| Запись пятибайтовых call | memcpy без остановки других потоков допускает исполнение частично изменённой инструкции | Единая транзакция после подтверждённой остановки всех остальных потоков |
| Выгрузка | Проверка archive_sessions_active и последующее снятие хуков разделены; возможен новый BeginAuthSession между ними | После фиксации хуков выгрузка/пауза запрещены до завершения процесса |
| Общие флаги/API | Обычные bool и повторная запись общих полей не задавали межпоточной публикации | Атомарный lifecycle CAS, acquire/release публикация неизменяемого API |
| TLS-маршрут | Один Selection на поток терял состояние при вложенном BeginAuthSession в этом же потоке | До 16 отдельных слотов по EBP нативного вызывающего кадра; однократное потребление и отказ при переполнении |
| Время жизни ELF-метаданных | Указатели dl_iterate_phdr использовались после завершения callback без закрепления зависимостей | Копирование пути, RTLD_NOLOAD/NODELETE закрепление engine/Steamclient и повторный снимок |

Безопасность hot unload не достигается одной проверкой числа сессий или одним
атомарным счётчиком: новый вызов может начаться сразу после проверки. Поэтому
активные хуки теперь имеют время жизни процесса. Отмена загрузки разрешена
только пока установка ещё не началась; CAS исключает одновременную отмену и
начало установки. Административный force unload и сторонняя запись в память
процесса не относятся к гарантированным операциям плагина.

## Проверка дубликатов

В поставленном steamclient.so штатный BeginAuthSession 0x4890e0 захватывает
pthread_mutex перед вызовами проверки 0x4891aa и регистрации 0x489325 и
освобождает его на нормальных выходах. EndAuthSession 0x489550 также держит
блокировку в момент вызова 0x48992d. Это проверяет tests/verify_native_lock.py
по графу нормального потока управления и SHA-256 бинарника.

Следовательно, дополнительный поиск второго CGameID и исходная регистрация
остаются одной критической секцией нативного GameServer. Отдельного кэша
SteamID или разрыва между проверкой и добавлением Bridge не вводит. Для одного
SteamID конкурентные 730/4465480 должны дать один успех и DuplicateRequest=2
остальным; EndAuthSession удаляет оба ключа.

## Установка хуков

ThreadQuiescence резервирует ранее неиспользуемый realtime-сигнал, адресно
уведомляет потоки через rt_tgsigqueueinfo и паркует их на futex. После
подтверждений список /proc/self/task перечитывается: это учитывает потоки,
созданные в момент первого обхода. Обработчик использует атомарные операции
и прямые системные вызовы, без аллокаций, stdio, динамического TLS и loader API.
Ограничение — 512 других потоков и 500 мс ожидания; при невозможности полной
остановки инструкции не изменяются. Просроченные private-уведомления несут
поколение операции и игнорируются. Сигнал и обработчик закреплены до конца
процесса, чтобы запоздалое уведомление не попало в восстановленный SIG_DFL.

Это опирается на Linux [адресную доставку сигналов](https://man7.org/linux/man-pages/man2/tgkill.2.html),
[атомарное ожидание futex](https://man7.org/linux/man-pages/man2/futex.2.html) и
[ограничения signal-safe кода](https://man7.org/linux/man-pages/man7/signal-safety.7.html).

Пока потоки остановлены, исходные инструкции проверяются повторно, права записи
запрашиваются для всех нужных страниц и только затем копируются все пять call.
Частичная ошибка выдачи прав происходит до записи инструкций. Временный RWX
доступ ограничен этой транзакцией, затем запрашивается RX.

Если ОС отказала в восстановлении RX уже после записи, сохраняется полный
согласованный набор из пяти хуков, плагин сообщает ошибку и требует перезапуск.
Частичный обратный патч, создающий смешанное состояние, не выполняется. Код и
зависимости остаются закреплены; выгрузка такого состояния отклоняется. Нельзя
обещать восстановление защиты памяти, если сама ОС отказывает в mprotect.

## Выполненные проверки

- Реальные потоки Windows, GCC, общий код Bridge: 16 потоков, 1500 раундов,
  24 000 попыток входа с обоими AppId; в каждом раунде ровно один успех.
  Нативные Steam-функции и внешний mutex в этом тесте моделируются.
- Реальные потоки: однократная инициализация при 32 претендентах; 500 гонок
  между началом отложенной установки и её отменой; отказ выгрузки Active/Installing.
- Эмуляция скомпилированного Linux i386 плагина: оба порядка AppId, состояния
  1/3, исходный DuplicateRequest, повторный вход после End, вложенные кадры,
  независимый TLS, отказ повторного потребления кадра, неизменность callback.
- Скомпилированный RT-обработчик выполнен на двух эмулированных CPU-контекстах:
  peer паркуется, все операции с текстом происходят при остановленном peer,
  затем peer возобновляется. Проверены тайм-аут, задержанное уведомление,
  отмена установки, отказы прав записи и восстановления RX.
- ELF32, только CreateInterface в экспортах, RELRO/NOW, NX stack, отсутствие
  C++ runtime в зависимостях; оригинальные engine/Steamclient не переписываются.

## Практические ограничения

Unicorn моделирует Linux syscalls и не заменяет проверку планировщика/сигналов
на настоящем Linux. Для неё подготовлен tests/concurrency_tests.cpp:

```text
python tools/build.py --stress
./build/tests/concurrency_tests.i386
```

На Linux i386 этот тест дополнительно выполняет реальные парковку/возобновление
потоков, 100 циклов quiescence, тайм-аут заблокированного сигнала и позднюю
доставку. В текущей Windows-среде эти Linux kernel-проверки не исполнялись.
Живой SRCDS, настоящие auth tickets и ответ Steam backend также не проверялись.
Отсутствие обнаруженных гонок в проверенных сценариях не доказывает их полного
отсутствия в движке, Steamclient, Metamod или сторонних плагинах.


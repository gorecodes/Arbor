# Arbor — Feature proposals

Data: 2026-05-22

Analisi delle feature potenzialmente utili da aggiungere ad Arbor, basata su:
- Audit della codebase (`backend/`, `frontend/alpine/`, documenti di piano esistenti).
- Confronto con il roadmap esistente (`ARBOR_ARCHITECTURE_ROADMAP.md`), che è interamente focalizzato su sicurezza/internet-readiness e non copre feature funzionali.
- Ricerca online su tool concorrenti (Porthole, Kuroo, Portato, Himerge — tutti dismessi da ~15 anni), pattern in package manager moderni (pamac, octopi, bauh), e pain point Gentoo discussi su wiki/forum.

## Stato della copertura

Arbor copre bene il core `emerge` (install/uninstall/world/depclean/sync/preserved-rebuild/autounmask) e storage (overlays, jobs SQLite, etc-update), ma lascia scoperti interi sotto-alberi di Portage e perde alcune opportunità "killer" che nessun tool oggi offre.

---

## A. Quick wins (effort basso, valore subito visibile)

| Feature | Perché vale | Implementazione |
|---|---|---|
| ~~**News items Portage** (GLEP 42)~~ ✅ **DONE (develop)** | Le news segnalano migrazioni critiche (profile 23.0, /usr-merge) che oggi gli utenti perdono. Sono file locali in `/var/db/repos/gentoo/metadata/news/`. | Tile dashboard + tab dedicata; daemon legge i `.txt` e il file `news-*.unread`. |
| ~~**GLSA security advisories** (`glsa-check -l`)~~ ✅ **DONE (develop)** | Allineato perfettamente con il modello daemon-root. Oggi Arbor non ha nessuna superficie sicurezza utente. | Endpoint `/api/glsa`, badge in dashboard con count "GLSA aperti che ti riguardano", azione "applica fix" che invoca il flow di approval. |
| ~~**Compile-time history (genlop/qlop)**~~ ✅ **DONE (v0.2.4)** | Dati già nel file `/var/log/emerge.log`; Arbor li parsa parzialmente in `emerge_log.py` per il dashboard, ma non mostra storia per pacchetto né ETA su install futura. | Estendere `emerge_log.py` con per-atom stats; mostrare grafico nel package detail; sommare la media per il set risolto e mostrare "ETA stimata" nella schermata di pretend. |
| ~~**Cache cleaner panel** (`eclean-dist`, `eclean-pkg`)~~ ✅ **DONE (develop)** | Distfiles/binpkg/kernel vecchi mangiano disco silenziosamente. Pattern standard in pamac/octopi. | Nuova sub-tab in `updates`; daemon esegue `eclean -d` con `--pretend` poi reale via approval. |

---

## B. Feature distintive (nessun altro tool web le fa oggi)

I tool storici (Porthole, Kuroo, Portato, Himerge) sono morti da ~15 anni. Arbor ha spazio per posizionarsi su use case che restano scoperti:

1. **Kernel update wizard** — gestione `gentoo-sources` vs `*-kernel` (distkernel), `oldconfig` diff, rebuild initramfs, `@module-rebuild`, pulizia `/boot`. Nessun tool grafico lo copre, ed è il workflow che genera più domande nel forum Gentoo.

2. ~~**Config snapshot export/import**~~ ✅ **DONE (develop)** — zip di `/etc/portage/`, `/var/lib/portage/world`, `make.profile` symlink. Tarballa lo stato "logico" della macchina. Killer feature per chi gestisce più macchine Gentoo; oggi tutti lo fanno a mano (vedi thread su forums.gentoo.org).

3. **Binhost-aware install preview** — Gentoo ha ora binhost ufficiale, e `--getbinpkg` è il path raccomandato. Mostrare prima dell'install "12 binpkg / 3 da sorgente / size N MB / ETA stimata" + toggle `--getbinpkg` per job è valore immediato.

4. **Scheduling UI** per sync/world-update/GLSA-scan via il daemon root (oggi gli utenti scrivono systemd timer o cron a mano). Arbor ha già il daemon root: esporre uno scheduler con "nightly sync + notifica" è naturale.

---

## C. Gap di copertura Portage (completare ciò che manca)

- **`revdep-rebuild`** — pannello con preview + run; flusso analogo a `preserved-rebuild` che già esiste.
- **`dispatch-conf`** alternativo a `etc-update` — ha rollback via RCS e auto-merge whitespace. Oggi `etc-update` è l'unico path.
- **`eselect` (profile, kernel, editor, language, news)** — pannello "System" nuovo; profile switch è particolarmente sensibile e merita guard rail.
- **USE flag history / audit log** — vedere chi/quando ha cambiato flag globali o per-package (oggi `package.use` è solo file).
- **Dependency graph visuale** — Portato lo aveva. `--tree` di emerge non è sostituto. Utile per debugging conflitti.
- **Queue / batch install** — staging di N atom prima di lanciare. Tutti i tool moderni hanno una "transaction view".

---

## D. Osservabilità avanzata

- **distcc/ccache live stats** (distcc stats server su :3633, ccache hit rate via `ccache -s`) — tile dashboard. Converte gli scettici sui benefici reali.
- **Top time-consumers** (chromium/rust/llvm/qtwebengine) con suggerimento "passa a binpkg per questi atom".
- **Disk-space forecast** distfiles + binpkg + `/var/tmp/portage`.

---

## Raccomandazione concreta

Se dovessi sceglierne **3 da fare prima**, in ordine:

1. **News + GLSA dashboard** — effort minimo, dati locali, allinea Arbor al modello "daemon-root utile per cose sicurezza-critiche".
2. **Compile-time history + ETA pre-install** — il parser `emerge_log.py` esiste già, estensione naturale; è la *killer feature osservabilità* per Gentoo ("dovrei andare a dormire?").
3. **Config snapshot export/import** — unico tool sul mercato a farlo in modo strutturato; differenziatore forte.

## Note importanti

- Tutte queste feature **convivono con il roadmap di sicurezza esistente** (E1–E6 in `ARBOR_ARCHITECTURE_ROADMAP.md`): non lo bloccano.
- Il documento `fix_approval.md` contiene però **bug critici sul flow attuale di approval** (terminal injection in `approval_cli.py:31`, approval token "decorativo", `job_cancel`/`history_delete` senza approval completo). Prima di aggiungere feature che invocano azioni privilegiate (kernel wizard, scheduler, dispatch-conf) andrebbero chiusi quei punti.

---

## Fonti

Tool concorrenti / storici:
- https://porthole.sourceforge.net/
- https://kuroo.org/
- https://en.wikipedia.org/wiki/Portage_(software)

Pattern e wiki Gentoo:
- https://www.gentoo.org/glep/glep-0042.html (news items)
- https://security.gentoo.org/glsa
- https://wiki.gentoo.org/wiki/Gentoo_Binary_Host_Quickstart
- https://wiki.gentoo.org/wiki/Kernel/Upgrade
- https://wiki.gentoo.org/wiki/Dispatch-conf
- https://wiki.gentoo.org/wiki/Preserved-rebuild
- https://wiki.gentoo.org/wiki/Eclean
- https://wiki.gentoo.org/wiki/Profile_(Portage)
- https://wiki.gentoo.org/wiki/Genlop
- https://wiki.gentoo.org/wiki/Distcc
- https://wiki.gentoo.org/wiki/Cfg-update

Discussioni community:
- https://forums.gentoo.org/viewtopic-t-926884-start-0.html (backup config)
- https://leo3418.github.io/2025/06/22/custom-gentoo-binhost.html
- https://fedang.net/posts/gentoo-kernel-upgrade/
- https://medium.com/@dme86/systemd-timer-with-emerge-sync-625833664866

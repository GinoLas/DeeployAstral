# Adattamento OpenTitan per il double buffering Deeploy

## File da integrare

- `Firmware/OpenTitan/firmware_async.c`: sostituisce il main allegato dall'utente;
  conserva inizializzazione AES/CSRNG/HMAC, configurazione PLIC e avvio cluster.
- `Firmware/OpenTitan/deeploy_ot_service.inc`: ISR, coda, worker, trasferimenti
  e completamenti. Viene incluso dal main; non compilarlo separatamente.
- `deeploy_ot_async_task.h`: ABI condivisa **su entrambi i lati**.
- `deeploy_ot_queue.h`, `deeploy_ot_ctr_copy.h`, `deeploy_ot_platform.h`: helper
  inclusi dal servizio.
- `firmware_original.c.txt`: copia inalterata dell'allegato per il confronto.
- `Firmware/OpenTitan/tests`: test host e verifica layout/primitive RV32.

Copiare questi file accanto al main nel progetto OT, mantenendo disponibili gli
header e i sorgenti della piattaforma usati dal firmware originale. Compilare
solo `firmware_async.c` come main. Questo repository non contiene il build OT,
gli header generati dei registri, lo startup o il linker script: non è stato
prodotto un ELF completo del firmware.

## Modifiche necessarie sul cluster

Nel runtime PULP includere `deeploy_ot_async_task.h` PRIMA del codice generato e
sostituire la definizione dell'oggetto condiviso:

```c
#include "deeploy_ot_async_task.h"
deeploy_ot_task_t cl_task; // sostituisce il precedente oggetto, non aggiungerne un secondo
```

Aggiornare anche eventuali dichiarazioni `extern` dello stesso oggetto. Non basta
aggiungere un `-D`: i campi e la dimensione devono coincidere. Ricompilare PULP e
OT insieme e rigenerare la rete con il codegen aggiornato.

Dalle definizioni fornite, `memory_transfer_operation_t` era di 32 byte e
`memory_transfer_operation_altered_t` di 40 byte su RV32. Il nuovo tipo è di
**48 byte**; gli assert verificano layout e dimensione:

| Offset | Campo |
| --- | --- |
| 0, 4 | src, dst |
| 8 | size |
| 12, 16 | src_stride, dst_stride |
| 20, 24 | repetitions, size_1d |
| 28 | transfer_id |
| 32, 36 | src_key, dst_key: base del tensore esterno |
| 40, 44 | completion_addr, completion_value |

Il firmware non modifica più l'oggetto del cluster. `src_key`/`dst_key` sono
riempiti dal codegen e NON vengono ricavati dallo slot L1 del primo tile.
Il formato dei messaggi rimane `mailbox_send(1, &cl_task, flags)`:

| Maschera | Uso preservato |
| --- | --- |
| 1 | geometria 2D |
| 2 | pesi |
| 4 | ingresso/decifratura |
| 8 | crittografia |
| 16 / 48 | init / clear |
| 64 / 256 | verifica HMAC / associazione IV dei pesi |
| 128 / 0xFF000000 | fine inferenza / avvio dall'host |

Il bit pesi continua a essere trasmesso, ma il worker usa la base esterna per
cercare i metadati di pesi e attivazioni. Nessun flag aggiuntivo in letter1.

## ISR e worker

L'ISR legge prima le lettere, copia l'intero descrittore in una FIFO privata e
solo dopo azzera SND_STAT. L'ACK significa **acquisito**, non **completato**.
La ISR non usa AES, iDMA, CSRNG, hashmap né attiva kernel.

Con coda piena, l'ISR memorizza le lettere, azzera solo l'interrupt ricezione e
lascia SND_STAT occupato. Il cluster mantiene il descrittore immutabile. Il
worker libera uno slot e acquisisce il messaggio sospeso prima di dare l'ACK.
La profondità predefinita è 8, configurabile con `OT_QUEUE_DEPTH`.

Il worker gira nel main con interrupt abilitati. Esegue una richiesta alla
volta; gli helper iDMA/AES possono restare sincroni perché il cluster e la ISR
continuano a lavorare. Tutti i comandi, inclusi init/clear/end, passano nella
stessa FIFO: non cancellano metadati o chiavi mentre una richiesta li usa.
Il worker fa polling quando inattivo per evitare la finestra fra controllo
coda vuota e WFI; un idle a interrupt potrà essere aggiunto con una sequenza
atomica specifica della piattaforma.

Alla fine di ogni richiesta dati, solo DOPO l'ultimo `wait_for_idma_eot`, il
worker pubblica `completion_value` all'indirizzo `completion_addr`. Le richieste
asincrone non generano eventi EU globali. I comandi di controllo conservano
l'evento `IDMA_EVENT`; HOST/END conservano il comportamento originale.

Il codegen DB ha un contatore per tensore e direzione. Anche il codegen SB usa
contatori quando il nuovo header definisce `DEEPLOY_OT_ASYNC_ABI`: i contatori SB
raggruppano i trasferimenti per direzione, mantenendo il loop single buffering.
Questo evita che il completamento del primo input venga scambiato per quello
di tutti gli input. Senza il nuovo header il codegen SB conserva il percorso
precedente, destinato al vecchio firmware. Il nuovo firmware NON è compatibile
con descrittori dati di 32/40 byte già compilati.

## Cifratura e tile parziali

Il precedente accumulo della matrice in plaintext a `0x80070000` è rimosso.
Ogni riga del tile viene cifrata e scritta subito. Una richiesta 2D con una sola
riga segue correttamente il bit direzione; non viene più forzata in cifratura.

La hashmap contiene solo associazioni `base esterna -> base, IV, chiave`.
`transfer_id` resta nel descrittore ma non è una chiave della hashmap. Ciò elimina
sia la dipendenza da ping/pong sia l'inserimento dei vecchi identificatori nello
stesso spazio delle chiavi crittografiche. Non servono modifiche all'API hashmap
fornita; il worker controlla il ritorno `HM_ERR_FULL`.

Per una nuova produzione di attivazioni, la prima richiesta deve cominciare
alla base esterna del tensore. Il worker genera IV e chiave nuovi in quel punto;
le richieste successive riusano gli stessi metadati. La normale tassellazione
completa di Deeploy comincia dalla base e soddisfa questo vincolo. Non usare
questo protocollo per aggiornamenti in-place/parziali di un vecchio tensore,
writeback sovrapposti o schedule che ripassano dalla base durante una stessa
produzione: serve un identificatore esplicito della generazione del tensore.
Pesi pre-cifrati continuano a usare il comando IV=256 e la chiave caricata.

L'offset CTR è sempre quello nella regione esterna:
`src - src_key` in ingresso, `dst - dst_key` in uscita, includendo lo stride
esterno delle righe. Il consumer può avere una tassellazione differente dal
producer. `add_u128_leword_visual` mantiene la convenzione dei contatori del
firmware fornito; la sua implementazione va verificata con i vettori AES reali.

L'implementazione hashmap deve copiare IV e chiave nei propri array, senza
conservare puntatori allo stack del worker, come suggerisce la struttura
HashEntry fornita. I sorgenti della hashmap non erano inclusi nella richiesta.

Il worker legge/esegue DMA/scrive ESATTAMENTE i byte richiesti, usando staging
per blocchi da 16 byte. Per gli offset non allineati si usano gli opportuni byte
del blocco CTR; non si anticipa `src` nello slot L1 e non si arrotonda un DMA
oltre la lunghezza del tile. L'AES resta in CTR con l'operazione ENC per entrambe
le direzioni, come nel firmware originale. Questa versione usa DMA piccoli
per blocco AES per rendere espliciti i limiti dei buffer: abilita l'overlap ma
non promette un aumento di throughput. Il batching sullo scratch potrà ridurre
l'overhead dopo la verifica della mappa TCDM.

Sono corretti anche due problemi del controllo originale: init con letter0=0
non dereferenzia il puntatore; un HMAC fallito arresta il worker senza pubblicare
un successo. Il caricamento della chiave HMAC, prima commentato, è attivo. Non
si stampano le chiavi nel percorso di associazione IV. Le attivazioni rimangono
protette con CTR come prima: non viene aggiunto un MAC per le attivazioni.

## Vincoli hardware da confermare sul target

- `OT_CLUSTER_ALIAS_BASE` usa `CLUSTER_SPM_BASE_ADDR` per tradurre gli indirizzi
  PULP inferiori a 0x50000000, inclusi descrittori, basi e completamenti. La
  traduzione originaria era applicata diversamente a src e dst; ora è uniforme.
  Verificare il valore reale in `cluster.h` e gli alias dello stack cluster.
- `OT_TCDM_CPU_WORD_STRIDE=4` conserva l'accesso CPU `tcdm[word*4]` osservato nel
  firmware originale. Gli indirizzi iDMA rimangono indirizzi byte. Se la vista
  CPU del TCDM è invece contigua, impostare 1. Servono mappa hardware e driver
  per confermare questo punto: non è stato dedotto un diverso layout.
- `mbox.h`/driver non sono stati forniti: verificare che RCV_CLR azzeri solo
  l'interrupt ricezione e SND_CLR liberi il sender, senza cancellare le lettere
  prima della copia. I test simulano esattamente questo contratto.
- `wait_for_idma_eot` deve garantire visibilità delle scritture. Gli helper AES,
  entropy e iDMA non devono mascherare gli interrupt per tutta l'elaborazione:
  altrimenti l'ACK della richiesta successiva si ritarda e l'overlap si riduce.
- Descrittore, buffer e parole completion devono essere condivisi e coerenti;
  i fence non sostituiscono manutenzione cache. Il firmware assume accessi
  atomici a 32 bit ai completamenti. Le parole restano vive fino al drain finale.
- Riservare il pool CSRNG preesistente a 0xe0004000 e lo scratch TCDM; verificare
  nel linker che la nuova FIFO non li sovrapponga. Per RV32 la FIFO da 8 elementi
  occupa 460 byte, più il descrittore attivo e lo stack AES.
- La tabella mantiene la capacità di 128 elementi e va dimensionata rispetto
  alle basi distinte della rete. Non viene implementata una politica di eviction.

## Attivazione e verifica

Per il runner con tiling: `--doublebuffer --defaultMemLevel L2` in
`DeeployTest/testMVP.py`. Con memoria predefinita L3 il runner sceglie ancora
`DBOnlyL3Tiler`, che lascia L1 single buffered. L'adattamento qui è per L2/L1;
non è stata validata la composizione con double buffering annidato L3/L2/L1.

Verifiche eseguite:

- test C della FIFO: copia privata, pieno/vuoto, ordine e wrap;
- 4224 combinazioni di offset/lunghezza per la copia CTR con controlli dei bordi;
- esecuzione del servizio reale con MMIO/iDMA/AES simulati: ACK prima del lavoro,
  IRQ durante un DMA, coda piena, completamenti e cifratura 2D con lettura a
  tassellazione diversa, 2D con una sola riga, rinnovo IV e mancata notifica su HMAC/geometria errati;
- compilazione RV32 del layout ABI, delle primitive fence/interrupt e delle chiamate 1D/2D generate da Deeploy nei percorsi SB e DB;
- test Python del codegen: flag, riferimenti, loop DB e profiling.

I test host usano un keystream sintetico, NON validano AES hardware, endianess,
CSRNG, HMAC o i driver reali. `Deeploy/CryptONNX.py` è assente nel checkout: solo
nei test del codegen è stato sostituito all'import con uno stub mai invocato.
Nessuna simulazione RTL, compilazione completa OT o prova sulla scheda eseguita.

Con un compilatore C host:

```sh
cc -std=c11 -Wall -Wextra -Werror Firmware/OpenTitan/tests/test_async_core.c -o test_core
cc -std=gnu11 -Wall -Wextra -Werror -Wno-unused-function Firmware/OpenTitan/tests/test_service.c -o test_service
./test_core
./test_service
```

Il test del servizio mappa memoria virtuale all'indirizzo 0x78000000; richiede
Windows o Linux con quell'intervallo libero. Sul target confrontare output SB/DB
per reti con più input, 1/2/molti tile, 2D/3D e bordi non allineati; tracciare
worker OT e `pi_cl_team_fork` per verificare l'intersezione temporale. Questa
modifica sovrappone OT e cluster; non parallelizza internamente AES e iDMA.

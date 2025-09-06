# Высокопроизводительный захват пакетов на Scapy

Проект предназначался, как микросервис для большого разрабатываемого DPI. Прототипирование решено было сделать на Python с использованием библиотеки Scapy. Реализован захват пакетов прямолинейно и через кольцевой буфер.
Основной алгорритм реализован high_performance_capture.py, были написаны скрипты для тестов test_pcap_capture (fixed).py.

Для запуска скрипта тестирования нужно указать параметр 

```bash
# Оба режима тестирования
python test_pcap_capture_fixed.py sample.pcap --mode both

# Только прямая обработка (быстрее и точнее)
python test_pcap_capture_fixed.py sample.pcap --mode direct

# Только буферная обработка
python test_pcap_capture_fixed.py sample.pcap --mode buffered
```

Pcap для тестов был записан и сохранён в Wireshark. Pcap должен находиться в папке проекта. 

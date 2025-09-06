#!/usr/bin/env python3
"""
Исправленный тестовый скрипт для проверки high_performance_capture.py с pcap файлами
Совместим с Windows и Linux
"""

import sys
import time
import argparse
import threading
from pathlib import Path
from typing import Dict, Any

try:
    import scapy.all as scapy
    from scapy.utils import rdpcap
except ImportError:
    print("Установите scapy: pip install scapy")
    sys.exit(1)

# Импорт нашего модуля
from high_performance_capture import (
    HighPerformanceCapture, 
    PacketMetadata, 
    CaptureStats
)

class FixedPcapTester:
    """Исправленный класс для тестирования захвата с pcap файлами"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = Path(pcap_file)
        self.packets = []
        self.processed_packets = []
        self.anomalies = []
        self.packets_sent = 0
        self.packets_failed = 0
        
        # Проверка существования файла
        if not self.pcap_file.exists():
            raise FileNotFoundError(f"Pcap файл не найден: {pcap_file}")
    
    def load_pcap(self):
        """Загрузка пакетов из pcap файла"""
        print(f"Загрузка pcap файла: {self.pcap_file}")
        try:
            self.packets = rdpcap(str(self.pcap_file))
            print(f"Загружено {len(self.packets)} пакетов")
        except Exception as e:
            print(f"Ошибка загрузки pcap: {e}")
            raise
    
    def packet_callback(self, metadata: PacketMetadata, packet_data: bytes):
        """Колбэк для обработки пакетов"""
        self.processed_packets.append({
            'metadata': metadata,
            'size': len(packet_data),
            'timestamp': metadata.timestamp
        })
        
        # Вывод информации о пакете (каждый 50-й для уменьшения спама)
        if len(self.processed_packets) % 50 == 0 or len(self.processed_packets) <= 10:
            protocol_name = {
                1: 'ICMP',
                6: 'TCP', 
                17: 'UDP'
            }.get(metadata.protocol, f'Protocol-{metadata.protocol}')
            
            print(f"[{len(self.processed_packets):4d}] "
                  f"{metadata.src_ip}:{metadata.src_port} -> "
                  f"{metadata.dst_ip}:{metadata.dst_port} "
                  f"({protocol_name}, {metadata.size} bytes)")
    
    def anomaly_callback(self, anomaly_data: Dict[str, Any]):
        """Колбэк для обработки аномалий"""
        self.anomalies.append(anomaly_data)
        print(f"🚨 АНОМАЛИЯ: {anomaly_data}")
    
    def simulate_capture_direct(self, delay: float = 0.001):
        """Прямая симуляция без использования сетевого захвата"""
        print(f"\nНачало прямой симуляции обработки пакетов...")
        
        # Создание процессора пакетов напрямую
        from high_performance_capture import PacketProcessor
        processor = PacketProcessor()
        
        start_time = time.time()
        processed_count = 0
        failed_count = 0
        
        try:
            for i, packet in enumerate(self.packets):
                packet_data = bytes(packet)
                
                # Прямая обработка пакета
                metadata = processor.process_packet(packet_data)
                if metadata:
                    self.packet_callback(metadata, packet_data)
                    processed_count += 1
                else:
                    failed_count += 1
                    print(f"⚠️  Пакет {i+1} не удалось обработать")
                
                # Задержка между пакетами
                if delay > 0:
                    time.sleep(delay)
                
                # Прогресс каждые 100 пакетов
                if (i + 1) % 100 == 0:
                    print(f"Обработано {i+1}/{len(self.packets)} пакетов...")
            
            processing_time = time.time() - start_time
            
            # Вывод статистики
            self.print_direct_statistics(processed_count, failed_count, processing_time)
            
        except KeyboardInterrupt:
            print("\n⏹️  Тест прерван пользователем")
    
    def simulate_capture_buffered(self, delay: float = 0.001):
        """Симуляция с использованием буферной системы (исправленная)"""
        print(f"\nНачало буферной симуляции захвата с задержкой {delay}s между пакетами...")
        
        # Создание кастомного захвата без сетевого интерфейса
        capture = MockHighPerformanceCapture()
        capture.add_packet_callback(self.packet_callback)
        capture.add_anomaly_callback(self.anomaly_callback)
        
        # Запуск только обработчиков (без сетевого захвата)
        capture.start_processing_only()
        
        try:
            start_time = time.time()
            
            # Подача пакетов в систему
            for i, packet in enumerate(self.packets):
                packet_data = bytes(packet)
                
                # Запись пакета в кольцевой буфер
                success = capture.ring_buffer.write_packet(packet_data)
                if success:
                    # Добавление в очередь обработки
                    try:
                        capture.processing_queue.put_nowait(packet_data)
                        capture.stats.packets_captured += 1
                        capture.stats.bytes_captured += len(packet_data)
                        self.packets_sent += 1
                    except:
                        capture.stats.packets_dropped += 1
                        self.packets_failed += 1
                        print(f"⚠️  Пакет {i+1} отброшен (очередь полна)")
                else:
                    capture.stats.packets_dropped += 1
                    self.packets_failed += 1
                    print(f"⚠️  Пакет {i+1} отброшен (буфер полон)")
                
                # Задержка между пакетами
                if delay > 0:
                    time.sleep(delay)
                
                # Прогресс каждые 100 пакетов
                if (i + 1) % 100 == 0:
                    print(f"Отправлено {i+1}/{len(self.packets)} пакетов...")
            
            # Ожидание завершения обработки
            print("\nОжидание завершения обработки...")
            time.sleep(3)
            
            # Ожидание очистки очереди
            timeout = 10
            while not capture.processing_queue.empty() and timeout > 0:
                time.sleep(0.5)
                timeout -= 0.5
                print(f"Очередь: {capture.processing_queue.qsize()} пакетов")
            
            processing_time = time.time() - start_time
            
            # Вывод статистики
            self.print_buffered_statistics(capture, processing_time)
            
        except KeyboardInterrupt:
            print("\n⏹️  Тест прерван пользователем")
        finally:
            capture.stop_capture()
    
    def print_direct_statistics(self, processed: int, failed: int, processing_time: float):
        """Статистика прямой обработки"""
        total = len(self.packets)
        success_rate = (processed / total) * 100 if total > 0 else 0
        
        print("\n" + "="*60)
        print("📊 СТАТИСТИКА ПРЯМОЙ ОБРАБОТКИ")
        print("="*60)
        
        print(f"📁 Pcap файл: {self.pcap_file.name}")
        print(f"📦 Пакетов в файле: {total}")
        print(f"⏱️  Время обработки: {processing_time:.2f} секунд")
        print(f"🚀 Скорость: {total/processing_time:.1f} пакетов/сек")
        
        print(f"\n📈 Результаты обработки:")
        print(f"  ✅ Успешно обработано: {processed}")
        print(f"  ❌ Не удалось обработать: {failed}")
        print(f"  📊 Успешность: {success_rate:.1f}%")
        
        self._print_protocol_stats()
    
    def print_buffered_statistics(self, capture, processing_time: float):
        """Статистика буферной обработки"""
        stats = capture.get_stats()
        total_packets = len(self.packets)
        processed_packets = len(self.processed_packets)
        
        # ИСПРАВЛЕНИЕ: правильный подсчёт потерянных пакетов
        actual_lost = total_packets - processed_packets
        
        print("\n" + "="*60)
        print("📊 СТАТИСТИКА БУФЕРНОЙ ОБРАБОТКИ")
        print("="*60)
        
        print(f"📁 Pcap файл: {self.pcap_file.name}")
        print(f"📦 Пакетов в файле: {total_packets}")
        print(f"⏱️  Время обработки: {processing_time:.2f} секунд")
        print(f"🚀 Скорость: {total_packets/processing_time:.1f} пакетов/сек")
        
        print("\n📈 Статистика захвата:")
        print(f"  📤 Отправлено в систему: {self.packets_sent}")
        print(f"  ✅ Захвачено системой: {stats.packets_captured}")
        print(f"  ⚙️  Успешно обработано: {processed_packets}")
        print(f"  ❌ Потеряно при отправке: {self.packets_failed}")
        print(f"  ❌ Потеряно при обработке: {stats.packets_dropped}")
        print(f"  🔍 РЕАЛЬНЫЕ потери: {actual_lost}")
        print(f"  📊 Байт захвачено: {stats.bytes_captured:,}")
        print(f"  🔄 Загрузка буфера: {capture.get_buffer_utilization():.1f}%")
        
        if self.anomalies:
            print(f"\n🚨 Обнаружено аномалий: {len(self.anomalies)}")
        
        self._print_protocol_stats()
        
        # Проверка целостности
        success_rate = (processed_packets / total_packets) * 100
        print(f"\n✅ Успешность обработки: {success_rate:.1f}%")
        
        if actual_lost > 0:
            print(f"\n⚠️  ВНИМАНИЕ: Потеряно {actual_lost} пакетов!")
            print("   Возможные причины:")
            print("   - Ошибки парсинга пакетов")
            print("   - Переполнение буферов")
            print("   - Неподдерживаемые протоколы")
        
        if success_rate < 95:
            print("⚠️  ВНИМАНИЕ: Низкая успешность обработки!")
        elif success_rate == 100:
            print("🎉 ОТЛИЧНО: Все пакеты обработаны успешно!")
    
    def _print_protocol_stats(self):
        """Вывод статистики по протоколам"""
        if not self.processed_packets:
            return
            
        protocols = {}
        for pkt_info in self.processed_packets:
            proto = pkt_info['metadata'].protocol
            protocols[proto] = protocols.get(proto, 0) + 1
        
        print("\n🌐 Распределение по протоколам:")
        protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        for proto, count in sorted(protocols.items()):
            name = protocol_names.get(proto, f'Protocol-{proto}')
            percentage = (count / len(self.processed_packets)) * 100
            print(f"  {name}: {count} ({percentage:.1f}%)")

class MockHighPerformanceCapture(HighPerformanceCapture):
    """Мок-версия захвата без сетевого интерфейса"""
    
    def __init__(self):
        super().__init__(interface=None)
    
    def start_processing_only(self):
        """Запуск только обработчиков без сетевого захвата"""
        if self.running:
            return
        
        self.running = True
        self.logger.info("Запуск обработчиков пакетов (без сетевого захвата)")
        
        # Запуск только потоков обработки
        for i in range(self.num_processing_threads):
            thread = threading.Thread(
                target=self._processing_worker,
                name=f"PacketProcessor-{i}"
            )
            thread.daemon = True
            thread.start()
            self.processing_threads.append(thread)
        
        self.logger.info(f"Запущено {self.num_processing_threads} потоков обработки")

def main():
    parser = argparse.ArgumentParser(
        description="Исправленное тестирование high_performance_capture.py с pcap файлами"
    )
    parser.add_argument(
        "pcap_file", 
        help="Путь к pcap файлу для тестирования"
    )
    parser.add_argument(
        "--delay", 
        type=float, 
        default=0.001,
        help="Задержка между пакетами в секундах (по умолчанию: 0.001)"
    )
    parser.add_argument(
        "--mode", 
        choices=["direct", "buffered", "both"],
        default="both",
        help="Режим тестирования: direct (прямая обработка), buffered (через буферы), both (оба)"
    )
    parser.add_argument(
        "--fast", 
        action="store_true",
        help="Быстрый режим без задержек"
    )
    
    args = parser.parse_args()
    
    if args.fast:
        args.delay = 0
    
    try:
        # Создание тестера
        tester = FixedPcapTester(args.pcap_file)
        
        # Загрузка pcap файла
        tester.load_pcap()
        
        # Запуск тестирования
        if args.mode in ["direct", "both"]:
            print("\n" + "="*60)
            print("🧪 ТЕСТ 1: ПРЯМАЯ ОБРАБОТКА")
            print("="*60)
            tester.simulate_capture_direct(delay=args.delay)
            
            # Сброс для второго теста
            if args.mode == "both":
                tester.processed_packets = []
                tester.anomalies = []
        
        if args.mode in ["buffered", "both"]:
            print("\n" + "="*60)
            print("🧪 ТЕСТ 2: БУФЕРНАЯ ОБРАБОТКА")
            print("="*60)
            tester.simulate_capture_buffered(delay=args.delay)
        
    except FileNotFoundError as e:
        print(f"❌ Ошибка: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 Тест завершён пользователем")
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
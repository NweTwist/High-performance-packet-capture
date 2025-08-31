#!/usr/bin/env python3
"""
Тестовый скрипт для проверки high_performance_capture.py с pcap файлами
"""

import sys
import time
import argparse
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

class PcapTester:
    """Класс для тестирования захвата с pcap файлами"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = Path(pcap_file)
        self.packets = []
        self.processed_packets = []
        self.anomalies = []
        
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
        
        # Вывод информации о пакете
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
    
    def simulate_capture(self, delay: float = 0.001):
        """Симуляция захвата пакетов из pcap файла"""
        print(f"\nНачало симуляции захвата с задержкой {delay}s между пакетами...")
        
        # Создание экземпляра захвата
        capture = HighPerformanceCapture()
        capture.add_packet_callback(self.packet_callback)
        capture.add_anomaly_callback(self.anomaly_callback)
        
        # Запуск системы захвата
        capture.start_capture()
        
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
                    except:
                        capture.stats.packets_dropped += 1
                else:
                    capture.stats.packets_dropped += 1
                    print(f"⚠️  Пакет {i+1} отброшен (буфер полон)")
                
                # Задержка между пакетами
                if delay > 0:
                    time.sleep(delay)
                
                # Прогресс каждые 100 пакетов
                if (i + 1) % 100 == 0:
                    print(f"Обработано {i+1}/{len(self.packets)} пакетов...")
            
            # Ожидание завершения обработки
            print("\nОжидание завершения обработки...")
            time.sleep(2)
            
            # Ожидание очистки очереди
            while not capture.processing_queue.empty():
                time.sleep(0.1)
            
            processing_time = time.time() - start_time
            
            # Вывод статистики
            self.print_statistics(capture, processing_time)
            
        except KeyboardInterrupt:
            print("\n⏹️  Тест прерван пользователем")
        finally:
            capture.stop_capture()
    
    def print_statistics(self, capture: HighPerformanceCapture, processing_time: float):
        """Вывод статистики тестирования"""
        stats = capture.get_stats()
        
        print("\n" + "="*60)
        print("📊 СТАТИСТИКА ТЕСТИРОВАНИЯ")
        print("="*60)
        
        print(f"📁 Pcap файл: {self.pcap_file.name}")
        print(f"📦 Пакетов в файле: {len(self.packets)}")
        print(f"⏱️  Время обработки: {processing_time:.2f} секунд")
        print(f"🚀 Скорость: {len(self.packets)/processing_time:.1f} пакетов/сек")
        
        print("\n📈 Статистика захвата:")
        print(f"  ✅ Захвачено: {stats.packets_captured}")
        print(f"  ⚙️  Обработано: {len(self.processed_packets)}")
        print(f"  ❌ Потеряно: {stats.packets_dropped}")
        print(f"  📊 Байт захвачено: {stats.bytes_captured:,}")
        print(f"  🔄 Загрузка буфера: {capture.get_buffer_utilization():.1f}%")
        
        if self.anomalies:
            print(f"\n🚨 Обнаружено аномалий: {len(self.anomalies)}")
            for i, anomaly in enumerate(self.anomalies[:5]):  # Показать первые 5
                print(f"  {i+1}. {anomaly}")
            if len(self.anomalies) > 5:
                print(f"  ... и ещё {len(self.anomalies) - 5}")
        
        # Анализ протоколов
        protocols = {}
        for pkt_info in self.processed_packets:
            proto = pkt_info['metadata'].protocol
            protocols[proto] = protocols.get(proto, 0) + 1
        
        if protocols:
            print("\n🌐 Распределение по протоколам:")
            protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            for proto, count in sorted(protocols.items()):
                name = protocol_names.get(proto, f'Protocol-{proto}')
                percentage = (count / len(self.processed_packets)) * 100
                print(f"  {name}: {count} ({percentage:.1f}%)")
        
        # Проверка целостности
        success_rate = (len(self.processed_packets) / len(self.packets)) * 100
        print(f"\n✅ Успешность обработки: {success_rate:.1f}%")
        
        if success_rate < 95:
            print("⚠️  ВНИМАНИЕ: Низкая успешность обработки!")
        elif success_rate == 100:
            print("🎉 ОТЛИЧНО: Все пакеты обработаны успешно!")

def main():
    parser = argparse.ArgumentParser(
        description="Тестирование high_performance_capture.py с pcap файлами"
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
        "--fast", 
        action="store_true",
        help="Быстрый режим без задержек"
    )
    
    args = parser.parse_args()
    
    if args.fast:
        args.delay = 0
    
    try:
        # Создание тестера
        tester = PcapTester(args.pcap_file)
        
        # Загрузка pcap файла
        tester.load_pcap()
        
        # Запуск симуляции
        tester.simulate_capture(delay=args.delay)
        
    except FileNotFoundError as e:
        print(f"❌ Ошибка: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 Тест завершён пользователем")
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()